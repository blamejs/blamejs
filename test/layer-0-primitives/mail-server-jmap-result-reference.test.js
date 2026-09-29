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
  // The name is refused for the whole request rather than for the one call,
  // because `b.guardJmap.validate` reads it before any method runs: nothing
  // downstream is handed an object carrying it, so no merge an operator
  // writes can move a prototype with it.
  var plainArgs = JSON.parse(
    '{"accountId":"' + ACCOUNT + '","__proto__":{"accountId":"SOMEONE-ELSE"}}');
  var plainSeen = [];
  var plainRv = await _server(plainSeen).dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", plainArgs, "c0"]],
  });
  check("a plain argument naming a prototype key is refused",
        plainRv.type === "urn:ietf:params:jmap:error:notRequest" && plainRv.status === 400,
        JSON.stringify(plainRv));
  check("and no handler ran at all",
        plainRv.methodResponses === undefined &&
        plainSeen.filter(function (c) { return c[0] === "Core/echo"; }).length === 0,
        JSON.stringify(plainSeen));

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

// A result reference NAMES a value rather than copying it, so resolving one
// shares the referenced subtree instead of duplicating it. Two references to the
// same prior call, repeated down a chain, therefore describe a DAG whose
// serialized form doubles at every step while the request grows by one short
// call. Measured before the budget: 16 calls turned a 2 KiB request into a 5.6 MB
// response, four times larger per call added, and the profile permits 32. None of
// the per-reference checks can see it: every descriptor is well formed and every
// depth is under `maxBackRefDepth`. The cost is cumulative, so the budget is too.
async function testChainedResultReferencesCannotOutgrowTheRequestCap() {
  function _chain(n) {
    var calls = [["Core/echo", { accountId: ACCOUNT, seed: "x".repeat(64) }, "c0"]];
    for (var i = 1; i < n; i += 1) {
      var prev = "c" + (i - 1);
      calls.push(["Core/echo", {
        accountId: ACCOUNT,
        "#a": { resultOf: prev, name: "Core/echo", path: "" },
        "#b": { resultOf: prev, name: "Core/echo", path: "" },
      }, "c" + i]);
    }
    return calls;
  }

  var deep = await _dispatch(_chain(24));
  // A method-level error carries the bare name RFC 8620 §3.6.2 prints, not the
  // request-level URI, which is what this release settled.
  var refused = deep.responses.filter(function (r) {
    return _errorOf(r) === "invalidResultReference";
  });
  check("a chain of doubling result references is refused before it expands",
        refused.length > 0, JSON.stringify(deep.responses.length));

  // The refusal has to bound the ANSWER, not merely appear in it.
  var bytes = JSON.stringify(deep.responses).length;
  check("and the response stays within the request cap it is measured against",
        bytes <= 10485760, JSON.stringify({ bytes: bytes }));

  // The control: the mechanism still works. A short chain of the same shape
  // expands to almost nothing and is answered in full.
  var ok = await _dispatch(_chain(4));
  var okErrors = ok.responses.filter(function (r) { return _errorOf(r) !== null; });
  check("a short chain of the same shape is still answered in full",
        okErrors.length === 0, JSON.stringify(okErrors.slice(0, 2)));

  // A budget is only useful if it measures what it claims to. Three ways the
  // first version of this one was wrong, each of which makes it either refuse
  // honest traffic or miss the traffic it exists to refuse.

  // Charging a flat width per primitive refuses a request the size validator
  // already admitted: 1.2 million zeros serialize to about 2.4 MB.
  var zeros = new Array(1200000).fill(0);
  var big = await _dispatch([["Core/echo", { accountId: ACCOUNT, zeros: zeros }, "z0"]]);
  check("a large reference-free request is measured at its real size, not a flat width",
        _errorOf(big.responses[0]) === null,
        JSON.stringify(_errorOf(big.responses[0])));

  // Counting UTF-16 code units misses JSON escaping: a NUL serializes as the
  // six bytes of \u0000, so a seed of them expanded far past the cap while the
  // budget believed it was spending one byte each.
  function _escapedChain(n) {
    var calls = [["Core/echo",
      { accountId: ACCOUNT, seed: "\u0000".repeat(64) }, "e0"]];
    for (var i = 1; i < n; i += 1) {
      var prev = "e" + (i - 1);
      calls.push(["Core/echo", {
        accountId: ACCOUNT,
        "#a": { resultOf: prev, name: "Core/echo", path: "" },
        "#b": { resultOf: prev, name: "Core/echo", path: "" },
      }, "e" + i]);
    }
    return calls;
  }
  var escaped = await _dispatch(_escapedChain(24));
  var escapedBytes = JSON.stringify(escaped.responses).length;
  check("an escaped string is charged what it serializes to, so the cap holds",
        escapedBytes <= 10485760, JSON.stringify({ bytes: escapedBytes }));

  // Spending the budget before checking it leaves it negative, so the refusal
  // of one call becomes the refusal of every later one, including calls that
  // carry no reference at all.
  var after = await _dispatch(_chain(24).concat([
    ["Core/echo", { accountId: ACCOUNT, ok: true }, "tail"],
  ]));
  var tail = after.responses[after.responses.length - 1];
  check("a call refused for its size does not spend the budget of the calls after it",
        _errorOf(tail) === null, JSON.stringify(tail));
}

// The budget was measured AFTER `_resolveBackRefs` returned, so a `*` had
// already built the whole array by the time anything refused it. A 120 KiB
// request with one 60,000-element array and 31 references to `/values/*` grew
// the heap by 66 MiB and was answered in full; at 4.5 MiB of wire it reached
// 444 MiB. The expansion is charged as each element is taken now, so the array
// is not materialized and then measured.
async function testAWildcardExpansionIsChargedAsItIsBuilt() {
  function _serverFor(name, values) {
    var methods = { "Core/echo": async function (actor, args) { return args; } };
    methods[name] = async function () { return { values: values }; };
    return b.mail.server.jmap.create({
      mailStore:   { appendMessage: function () {} },
      accountsFor: async function () {
        return { primaryAccounts: { mail: ACCOUNT }, accounts: { A1: { name: "one" } } };
      },
      methods: methods,
    });
  }

  function _expand(srv, name, clientId) {
    return srv.dispatch({ id: "actor1" }, {
      using:       ["urn:ietf:params:jmap:core"],
      methodCalls: [
        [name, { accountId: ACCOUNT }, clientId],
        ["Core/echo", { accountId: ACCOUNT,
          "#values": { resultOf: clientId, name: name, path: "/values/*" } }, clientId + "b"],
      ],
    });
  }

  // Counting getters, so this can see how far the expansion got rather than
  // infer it from the answer. 200 elements of 64 KiB come to 12.8 MB, past the
  // 10 MiB a request may reach.
  var reads = 0;
  var chunk = "x".repeat(65536);
  var wide = [];
  for (var i = 0; i < 200; i += 1) {
    Object.defineProperty(wide, i, {
      enumerable: true, configurable: true,
      get: function () { reads += 1; return chunk; },
    });
  }
  wide.length = 200;

  var wideRv = await _expand(_serverFor("Core/wide", wide), "Core/wide", "w0");
  check("a `*` expansion past the request cap is refused",
        _errorOf(wideRv.methodResponses[1]) === "invalidResultReference",
        JSON.stringify(wideRv.methodResponses[1]).slice(0, 200));
  check("and it stopped while building, rather than reading every element first",
        reads > 0 && reads < 200, JSON.stringify({ reads: reads, length: 200 }));

  // The budget counts JSON bytes, and an array of bare numbers costs two bytes
  // each on the wire and far more than that in memory. Charged at their wire
  // width alone, 700,000 zeros expand inside a 10 MiB budget while allocating
  // hundreds of megabytes, so each element carries a floor.
  var zerosRv = await _expand(_serverFor("Core/zeros", new Array(700000).fill(0)),
                              "Core/zeros", "z0");
  check("an expansion of many tiny elements is refused on the per-element floor",
        _errorOf(zerosRv.methodResponses[1]) === "invalidResultReference",
        JSON.stringify(_errorOf(zerosRv.methodResponses[1])));

  // The control for both: an expansion that fits is answered in full, so the
  // floor has not simply refused every wildcard.
  var okRv = await _expand(_serverFor("Core/small", new Array(1000).fill(0)),
                           "Core/small", "s0");
  check("an expansion that fits is answered in full",
        _errorOf(okRv.methodResponses[1]) === null &&
        okRv.methodResponses[1][1].values.length === 1000,
        JSON.stringify(_errorOf(okRv.methodResponses[1])));

  // Siblings inside ONE call draw on one budget. Each `#` argument used to get
  // the whole remaining request budget to itself, so the allocation grew with
  // how many references the call carried while the call was still refused:
  // measured at 0.77 MiB of wire, twenty references to one 400,000-element
  // array grew the heap 139 MiB and sixty grew it 318 MiB.
  // 100 elements of 64 KiB is 6.5 MB, so ONE expansion fits inside the 10 MiB
  // a request may reach and four together do not. That is the shape the defect
  // needed: every sibling passing its own check while their sum does not.
  var sibReads = 0;
  var sibChunk = "y".repeat(65536);
  var sibSource = [];
  for (var s = 0; s < 100; s += 1) {
    Object.defineProperty(sibSource, s, {
      enumerable: true, configurable: true,
      get: function () { sibReads += 1; return sibChunk; },
    });
  }
  sibSource.length = 100;

  var sibSrv = _serverFor("Core/sib", sibSource);
  var sibArgs = { accountId: ACCOUNT };
  for (var r = 0; r < 4; r += 1) {
    sibArgs["#r" + r] = { resultOf: "n0", name: "Core/sib", path: "/values/*" };
  }
  var sibRv = await sibSrv.dispatch({ id: "actor1" }, {
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [
      ["Core/sib", { accountId: ACCOUNT }, "n0"],
      ["Core/echo", sibArgs, "n1"],
    ],
  });
  check("a call whose sibling references overrun the budget is refused",
        _errorOf(sibRv.methodResponses[1]) === "invalidResultReference",
        JSON.stringify(_errorOf(sibRv.methodResponses[1])));
  // Sharing one budget, the call stops partway through the second sibling at
  // roughly 160 reads. Holding one budget each, all four expand in full — 400
  // reads — and only the check that runs afterwards refuses the call.
  check("and the four siblings drew on one budget rather than four",
        sibReads > 0 && sibReads < 300,
        JSON.stringify({ reads: sibReads, siblings: 4, perSibling: 100 }));
}

async function run() {
  await testAWildcardExpansionIsChargedAsItIsBuilt();
  await testChainedResultReferencesCannotOutgrowTheRequestCap();
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
