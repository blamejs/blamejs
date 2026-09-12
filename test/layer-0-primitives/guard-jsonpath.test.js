// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function testSanitize() {
  // Benign: a plain RFC 9535 member/wildcard path carries no code-
  // execution shape — sanitize returns it byte-for-byte (JSONPath
  // strings can't be repaired, so the transform is pass-through).
  var safe = b.guardJsonpath.sanitize("$.users[*].name", { profile: "strict" });
  check("guardJsonpath.sanitize benign passthrough",  safe === "$.users[*].name");
  check("guardJsonpath.sanitize benign type",         typeof safe === "string");

  // Hostile: `?(...)` filter expression — the dynamic-code-execution
  // class in legacy JSONPath evaluators. Refused at every profile;
  // never returned as a "cleaned" string.
  var filterErr = expectThrows("guardJsonpath.sanitize filter-expression throws",
    function () { b.guardJsonpath.sanitize("$..[?(@.x)]", { profile: "strict" }); },
    "jsonpath.filter-expression");
  check("guardJsonpath.sanitize filter GuardJsonpathError",
    filterErr instanceof b.guardJsonpath.GuardJsonpathError);

  // Hostile: JS-source hint (dynamic-code-exec keyword) embedded in the
  // path — refused as a code-injection attempt.
  expectThrows("guardJsonpath.sanitize dynamic-hint throws",
    function () { b.guardJsonpath.sanitize("$[eval]", { profile: "strict" }); },
    "jsonpath.dynamic-hint");

  // Hostile: bare script-expression shape `(@.x)` — aliased to filter
  // in several implementations; refused under strict.
  expectThrows("guardJsonpath.sanitize script-expression throws",
    function () { b.guardJsonpath.sanitize("$[(@.length-1)]", { profile: "strict" }); },
    "jsonpath.script-expression");

  // Hostile: 3+ consecutive `[` — parser-DoS shape, high under strict.
  expectThrows("guardJsonpath.sanitize bracket-nesting throws",
    function () { b.guardJsonpath.sanitize("$[[[0]]]", { profile: "strict" }); },
    "jsonpath.bracket-nesting");

  // The RCE class is refused regardless of profile — a permissive
  // caller can loosen recursive-descent depth but never the filter/
  // script/dynamic-hint refusal.
  expectThrows("guardJsonpath.sanitize filter refused at permissive too",
    function () { b.guardJsonpath.sanitize("$..[?(@.x)]", { profile: "permissive" }); },
    "jsonpath.filter-expression");
}

// RFC 9535 writes a filter selector as `?` followed by a logical expression;
// the parentheses of the older syntax are optional. The detector searched for
// the two characters `?(`, so `[?@.price<10]` passed clean at every profile
// while `[?(@.price<10)]` was critical, and b.jsonPath.query returns the same
// result for both. The descendant segment is `..` whatever selector follows,
// and the counter required a `*`, so twenty named descents scored zero.
function testDetectorsMatchTheConstructNotOneSpelling() {
  var DATA = { store: { book: [{ price: 5, title: "cheap" }, { price: 50, title: "dear" }] } };
  var parenLess = "$.store.book[?@.price<10].title";
  var parened = "$.store.book[?(@.price<10)].title";
  check("both filter spellings evaluate to the same thing",
        JSON.stringify(b.jsonPath.query(DATA, parenLess)) ===
        JSON.stringify(b.jsonPath.query(DATA, parened)));
  // A selector list puts one selector after another in a single bracketed
  // segment, so a filter can begin after a comma as well as after the opening
  // bracket. Anchoring only on `[` lost `$[0,?(!@.x)]`, which b.jsonPath.query
  // evaluates.
  [parenLess, parened, "$[? @.a]", "$[0,?(!@.x)]", "$[0, ?@.x]",
   "$['a',?@.x]", "$[?@.x,1]"].forEach(function (expr) {
    ["strict", "balanced", "permissive"].forEach(function (profile) {
      var rv = b.guardJsonpath.validate(expr, { profile: profile });
      check("filter expression refused at " + profile + " for " + JSON.stringify(expr),
            rv.ok === false &&
            rv.issues.some(function (i) { return i.kind === "filter-expression"; }),
            JSON.stringify(rv.issues.map(function (i) { return i.kind; })));
    });
  });

  var many = "$..a..b..c..d..e..f..g..h..i..j..k..l..m..n..o..p..q..r..s..t";
  ["strict", "balanced"].forEach(function (profile) {
    var rv = b.guardJsonpath.validate(many, { profile: profile });
    check("named recursive descents count toward the cap at " + profile,
          rv.issues.some(function (i) { return i.kind === "recursive-descent-cap"; }),
          JSON.stringify(rv.issues.map(function (i) { return i.kind; })));
  });
  check("wildcard descents still counted",
        b.guardJsonpath.validate("$..[*]..[*]..[*]", { profile: "strict" })
          .issues.some(function (i) { return i.kind === "recursive-descent-cap"; }));
  check("permissive allows recursive descent by policy",
        b.guardJsonpath.validate(many, { profile: "permissive" }).ok === true);

  // Ordinary paths, including a single descent and a quoted name holding no
  // filter, stay accepted. A quoted member name is data, so selector
  // characters inside one are not selector syntax: widening the two scanners
  // to match the construct made them read the brackets and dots inside a
  // quoted name as operators and refuse ordinary property lookups.
  ["$.store.book[0].title", "$.a.b.c", "$['quoted name'].x", "$..author",
   "$.store.book[*].title", '$["[?"]', "$['[?']", '$["a..b..c..d"]',
   '$["x"]["y"]', '$["a.b"].c', "$['a,b'].c", '$["x,?y"]',
   "$[0,1,2]"].forEach(function (expr) {
    check("ordinary path accepted " + JSON.stringify(expr),
          b.guardJsonpath.validate(expr, { profile: "strict" }).ok === true,
          JSON.stringify(b.guardJsonpath.validate(expr, { profile: "strict" })
            .issues.map(function (i) { return i.kind; })));
  });
}

async function run() {
  testSanitize();
  testDetectorsMatchTheConstructNotOneSpelling();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
