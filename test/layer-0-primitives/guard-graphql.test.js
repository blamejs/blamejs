// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var BENIGN_REQ = { query: "query GetMe { me { id name } }", operationName: "GetMe" };

// Introspection leak — `__schema` in production posture. Strict refuses.
var INTROSPECT_REQ = {
  query: "query Inspect { __schema { types { name } } }",
  operationName: "Inspect",
};

// Alias-amplification — 9 aliases in one selection-set exceeds strict's
// maxAliasesPerSelection (8); the breadth-DoS class.
var ALIAS_BOMB_REQ = {
  query: "{ a:me { id } b:me { id } c:me { id } d:me { id } e:me { id } " +
         "f:me { id } g:me { id } h:me { id } i:me { id } }",
};

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

async function testGate() {
  var gqlGate = b.guardGraphql.gate({ profile: "strict" });

  // Introspection query → refuse before any schema-resolution work.
  var introspect = await gqlGate.check({ graphqlRequest: INTROSPECT_REQ });
  check("guardGraphql.gate introspection action=refuse", introspect.action === "refuse");
  check("guardGraphql.gate introspection ok=false",      introspect.ok === false);
  check("guardGraphql.gate introspection ruleId",
    introspect.issues.some(function (i) { return i.ruleId === "graphql.introspection"; }));

  // Benign named query → serve.
  var serve = await gqlGate.check({ graphqlRequest: BENIGN_REQ });
  check("guardGraphql.gate benign action=serve",         serve.action === "serve");
  check("guardGraphql.gate benign ok=true",              serve.ok === true);

  // Alias bomb → refuse (breadth-amplification DoS).
  var bomb = await gqlGate.check({ graphqlRequest: ALIAS_BOMB_REQ });
  check("guardGraphql.gate alias-bomb action=refuse",    bomb.action === "refuse");
  check("guardGraphql.gate alias-bomb ruleId",
    bomb.issues.some(function (i) { return i.ruleId === "graphql.alias-bomb"; }));

  // No request on ctx → serve (nothing to gate).
  var none = await gqlGate.check({});
  check("guardGraphql.gate no-request action=serve",     none.action === "serve");
}

function testSanitize() {
  // Benign request passes through unchanged (bundles aren't repairable, so
  // sanitize is pass-through-or-throw); the returned bundle re-validates clean.
  var clean = b.guardGraphql.sanitize(BENIGN_REQ, { profile: "strict" });
  check("guardGraphql.sanitize benign returns bundle",   clean === BENIGN_REQ);
  check("guardGraphql.sanitize benign revalidates ok",
    b.guardGraphql.validate(clean, { profile: "strict" }).ok === true);

  // Hostile: introspection query REFUSED (thrown), never returned — the leak
  // shape is a refuse-class outcome, not something sanitize patches up.
  var err = expectThrows("guardGraphql.sanitize introspection throws",
    function () { b.guardGraphql.sanitize(INTROSPECT_REQ, { profile: "strict" }); },
    "graphql.introspection");
  check("guardGraphql.sanitize introspection GuardGraphqlError",
    err instanceof b.guardGraphql.GuardGraphqlError);

  // Hostile: prototype-pollution gadget in a query alias (CVE-2026-32621) —
  // critical, refused at every profile.
  expectThrows("guardGraphql.sanitize proto-poison throws",
    function () {
      b.guardGraphql.sanitize({ query: "query { a:__proto__ { id } }" }, { profile: "strict" });
    },
    "graphql.query-prototype-poison");
}

async function run() {
  await testGate();
  testSanitize();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
