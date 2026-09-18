// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A JMAP result reference resolves the way RFC 8620 section 3.7 defines it.
 *
 * `*` applies the rest of the pointer to every item of the array and
 * flattens array results into one array, so the chain the RFC uses as its
 * example, Email/query to Email/get to Thread/get to Email/get through
 * `/list/*<!---->/threadId` and `/list/*<!---->/emailIds`, passes thread ids
 * and message ids. The resolver returned the array itself as soon as it read
 * `*` and dropped the tokens after it, so each handler received the previous
 * method's objects instead. A path that names a property no item has must
 * fail the whole method with `invalidResultReference` rather than resolve to
 * the array, an array index follows the RFC 6901 grammar (`0`, or digits
 * with no leading zero), and an arguments object carrying both `ids` and
 * `#ids` is `invalidArguments`.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// The responses the RFC's example walks through.
var EMAILS = [
  { id: "m1", threadId: "t1" },
  { id: "m2", threadId: "t2" },
];
var THREADS = [
  { id: "t1", emailIds: ["m1", "m3"] },
  { id: "t2", emailIds: ["m2"] },
];

function _server(seen) {
  return b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
    methods: {
      "Email/get":  async function (actor, args) { seen.push(["Email/get", args]);  return { list: EMAILS }; },
      "Thread/get": async function (actor, args) { seen.push(["Thread/get", args]); return { list: THREADS }; },
      "Core/echo":  async function (actor, args) { seen.push(["Core/echo", args]);  return args; },
    },
  });
}

async function _dispatch(calls) {
  var seen = [];
  // Only the core capability: the server refuses a request that declares a
  // capability it does not advertise, and this test is about the resolver.
  var rv = await _server(seen).dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: calls,
  });
  return { seen: seen, responses: rv.methodResponses };
}

function _errorOf(response) {
  if (!response) return null;
  if (response[0] === "error") return (response[1] && (response[1].type || response[1].code)) || "error";
  return null;
}

async function testStarMapsTheRestOfThePointer() {
  var run = await _dispatch([
    ["Email/get", { ids: ["m1", "m2"] }, "c0"],
    ["Thread/get", { "#ids": { resultOf: "c0", name: "Email/get", path: "/list/*/threadId" } }, "c1"],
  ]);
  var threadArgs = run.seen.filter(function (c) { return c[0] === "Thread/get"; })[0];
  check("a * path maps the rest of the pointer over the array",
        threadArgs !== undefined &&
        JSON.stringify(threadArgs[1].ids) === JSON.stringify(["t1", "t2"]),
        threadArgs && JSON.stringify(threadArgs[1].ids));
}

async function testStarFlattensArrayResults() {
  var run = await _dispatch([
    ["Thread/get", { ids: ["t1", "t2"] }, "c0"],
    ["Core/echo", { "#ids": { resultOf: "c0", name: "Thread/get", path: "/list/*/emailIds" } }, "c1"],
  ]);
  var echo = run.seen.filter(function (c) { return c[0] === "Core/echo"; })[0];
  check("a * path flattens array results into one array",
        echo !== undefined &&
        JSON.stringify(echo[1].ids) === JSON.stringify(["m1", "m3", "m2"]),
        echo && JSON.stringify(echo[1].ids));
}

async function testAPathNoItemSatisfiesIsRejected() {
  var run = await _dispatch([
    ["Email/get", { ids: ["m1", "m2"] }, "c0"],
    ["Core/echo", { "#ids": { resultOf: "c0", name: "Email/get", path: "/list/*/nosuch" } }, "c1"],
  ]);
  var second = run.responses[1];
  check("a * path whose tail names nothing is invalidResultReference",
        /invalidResultReference/.test(_errorOf(second) || ""),
        JSON.stringify(second));
  check("the method that could not resolve did not run",
        run.seen.filter(function (c) { return c[0] === "Core/echo"; }).length === 0);
}

async function testArrayIndexFollowsTheRfc6901Grammar() {
  var wrong = [];
  var CASES = [
    { path: "/list/0/id",  want: "m1" },
    { path: "/list/1/id",  want: "m2" },
    { path: "/list/01/id", want: null },
    { path: "/list/1x/id", want: null },
    { path: "/list/+1/id", want: null },
  ];
  for (var i = 0; i < CASES.length; i += 1) {
    var run = await _dispatch([
      ["Email/get", { ids: ["m1", "m2"] }, "c0"],
      ["Core/echo", { "#id": { resultOf: "c0", name: "Email/get", path: CASES[i].path } }, "c1"],
    ]);
    var echo = run.seen.filter(function (c) { return c[0] === "Core/echo"; })[0];
    if (CASES[i].want === null) {
      if (!/invalidResultReference/.test(_errorOf(run.responses[1]) || "")) {
        wrong.push(CASES[i].path + " resolved to " + JSON.stringify(echo && echo[1].id));
      }
    } else if (echo === undefined || echo[1].id !== CASES[i].want) {
      wrong.push(CASES[i].path + " gave " + JSON.stringify(echo && echo[1].id));
    }
  }
  check("an array index follows the RFC 6901 grammar" +
        (wrong.length ? " (" + wrong.join("; ") + ")" : ""), wrong.length === 0);
}

async function testBothFormsOfAnArgumentAreRejected() {
  var run = await _dispatch([
    ["Email/get", { ids: ["m1", "m2"] }, "c0"],
    ["Core/echo", {
      ids:   ["literal"],
      "#ids": { resultOf: "c0", name: "Email/get", path: "/list/*/id" },
    }, "c1"],
  ]);
  check("an argument given in both forms is invalidArguments",
        /invalidArguments/.test(_errorOf(run.responses[1]) || ""),
        JSON.stringify(run.responses[1]));
  check("the method with both forms did not run",
        run.seen.filter(function (c) { return c[0] === "Core/echo"; }).length === 0);
}

async function run() {
  await testStarMapsTheRestOfThePointer();
  await testStarFlattensArrayResults();
  await testAPathNoItemSatisfiesIsRejected();
  await testArrayIndexFollowsTheRfc6901Grammar();
  await testBothFormsOfAnArgumentAreRejected();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-jmap-result-reference] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
