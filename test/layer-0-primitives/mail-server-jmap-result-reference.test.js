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

// Every method here is account-scoped, so each call names the one account
// the actor holds; RFC 8620 section 1.6.2 makes accountId mandatory.
var ACCOUNT = "A1";

function _server(seen) {
  return b.mail.server.jmap.create({
    mailStore:   { appendMessage: function () {} },
    accountsFor: async function () {
      return { primaryAccounts: { mail: ACCOUNT }, accounts: { A1: { name: "one" } } };
    },
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
    ["Email/get", { accountId: ACCOUNT, ids: ["m1", "m2"] }, "c0"],
    ["Thread/get", { accountId: ACCOUNT, "#ids": { resultOf: "c0", name: "Email/get", path: "/list/*/threadId" } }, "c1"],
  ]);
  var threadArgs = run.seen.filter(function (c) { return c[0] === "Thread/get"; })[0];
  check("a * path maps the rest of the pointer over the array",
        threadArgs !== undefined &&
        JSON.stringify(threadArgs[1].ids) === JSON.stringify(["t1", "t2"]),
        threadArgs && JSON.stringify(threadArgs[1].ids));
}

async function testStarFlattensArrayResults() {
  var run = await _dispatch([
    ["Thread/get", { accountId: ACCOUNT, ids: ["t1", "t2"] }, "c0"],
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
    ["Email/get", { accountId: ACCOUNT, ids: ["m1", "m2"] }, "c0"],
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
      ["Email/get", { accountId: ACCOUNT, ids: ["m1", "m2"] }, "c0"],
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
    ["Email/get", { accountId: ACCOUNT, ids: ["m1", "m2"] }, "c0"],
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

async function testAPoisonedTargetKeyIsNotWrittenThroughThePrototype() {
  // The resolver writes the resolved value with obj[key.slice(1)], and the
  // client picks that key. `#__proto__` therefore reached the prototype
  // SETTER of the arguments object rather than an own property: the handler
  // read accountId and every other argument off a prototype the caller
  // supplied, while hasOwnProperty said the object carried none of them.
  // accountId is the argument the account gate checks.
  var run = await _dispatch([
    ["Core/echo", { list: [{ accountId: "SOMEONE-ELSE" }] }, "c0"],
    ["Core/echo", { accountId: ACCOUNT,
                    "#__proto__": { resultOf: "c0", name: "Core/echo", path: "/list/0" } }, "c1"],
  ]);
  var echoes = run.seen.filter(function (c) { return c[0] === "Core/echo"; });
  var args = echoes.length > 1 ? echoes[1][1] : null;
  check("a back-reference naming a prototype key is refused",
        _errorOf(run.responses[1]) !== null,
        JSON.stringify(run.responses[1]));
  check("and no arguments object is handed over carrying a foreign prototype",
        args === null || Object.getPrototypeOf(args) === Object.prototype ||
          Object.getPrototypeOf(args) === null,
        args ? JSON.stringify(Object.getPrototypeOf(args)) : "method did not run");
  check("so accountId still reads as the one the call named",
        args === null || args.accountId === ACCOUNT,
        args ? JSON.stringify(args.accountId) : "method did not run");

  // The plain spelling reaches the same setter: the back-ref branch is one of
  // two places the client's key is written, and the other is every ordinary
  // argument.
  // Built through JSON, which is how a request arrives: in an object LITERAL
  // `__proto__:` sets the prototype at construction and is never an own key,
  // so a literal cannot model the shape the wire produces.
  var plainArgs = JSON.parse(
    '{"accountId":"' + ACCOUNT + '","__proto__":{"accountId":"SOMEONE-ELSE"}}');
  var plain = await _dispatch([["Core/echo", plainArgs, "c0"]]);
  var plainEchoes = plain.seen.filter(function (c) { return c[0] === "Core/echo"; });
  check("a plain argument naming a prototype key is refused",
        _errorOf(plain.responses[0]) !== null, JSON.stringify(plain.responses[0]));
  check("and the handler did not run with a foreign prototype",
        plainEchoes.length === 0 ||
          Object.getPrototypeOf(plainEchoes[0][1]) === Object.prototype ||
          Object.getPrototypeOf(plainEchoes[0][1]) === null,
        plainEchoes.length ? JSON.stringify(Object.getPrototypeOf(plainEchoes[0][1])) : "did not run");

  // The refusal answers one question, whether the key moves the prototype,
  // and `__proto__` is the only key that does: assigning `constructor` or
  // `prototype` to a fresh object makes an ordinary own property and leaves
  // the prototype alone. Both are legal names on the wire, `constructor` is
  // ATOM-CHARs so RFC 8621 section 4.1.1 admits it as a keyword and RFC 8620
  // section 1.2 admits it as a creation id, and RFC 8620 section 4.3.1 says
  // Core/echo answers with the arguments it was sent. Refusing them rejected
  // conformant clients for a hazard their names do not carry.
  var LEGAL_NAMES = ["constructor", "prototype", "valueOf", "hasOwnProperty"];
  for (var n = 0; n < LEGAL_NAMES.length; n += 1) {
    var legalArgs = JSON.parse(
      '{"accountId":"' + ACCOUNT + '","' + LEGAL_NAMES[n] + '":true}');
    var legal = await _dispatch([["Core/echo", legalArgs, "c0"]]);
    check("an argument named " + LEGAL_NAMES[n] + " is echoed rather than refused",
          _errorOf(legal.responses[0]) === null, JSON.stringify(legal.responses[0]));
    var legalSeen = legal.seen.filter(function (c) { return c[0] === "Core/echo"; });
    check("and the handler received it as an own property (" + LEGAL_NAMES[n] + ")",
          legalSeen.length === 1 &&
            Object.prototype.hasOwnProperty.call(legalSeen[0][1], LEGAL_NAMES[n]),
          legalSeen.length ? JSON.stringify(Object.keys(legalSeen[0][1])) : "did not run");
  }

  // The pointer segments are client-supplied too, and walking one through a
  // prototype key reads Object.prototype rather than a prior result.
  var walked = await _dispatch([
    ["Core/echo", { list: [{ id: "m1" }] }, "c0"],
    ["Core/echo", { accountId: ACCOUNT,
                    "#ids": { resultOf: "c0", name: "Core/echo", path: "/__proto__" } }, "c1"],
  ]);
  check("a pointer segment naming a prototype key is refused",
        _errorOf(walked.responses[1]) !== null,
        JSON.stringify(walked.responses[1]));
}

async function run() {
  await testStarMapsTheRestOfThePointer();
  await testAPoisonedTargetKeyIsNotWrittenThroughThePrototype();
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
