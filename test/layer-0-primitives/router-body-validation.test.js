// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// SMOKE_RUN_SOLO: growth checks here compare wall-clock time across input sizes, which a CPU shared with the smoke pool distorts.
/**
 * b.router — request-body schema validation must run even when no body was
 * parsed. A route declaring `spec.body` is asserting the body is part of the
 * contract; skipping the check when `req.body === undefined` (no body sent /
 * bodyParser absent / empty POST) silently admits a request that omits a
 * required body straight to the handler. Mirrors the always-run params/query
 * checks.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var s       = b.safeSchema;

function _req(method, url) {
  return { method: method, url: url, headers: { host: "localhost" } };
}

function _res() {
  var res = {
    statusCode:    0,
    headersSent:   false,
    writableEnded: false,
    _body:         "",
    writeHead: function (status, headers) {
      res.statusCode = status;
      res._headers = headers || {};
      res.headersSent = true;
    },
    end: function (chunk) {
      if (chunk !== undefined) res._body += chunk;
      res.writableEnded = true;
    },
  };
  return res;
}

async function testMissingRequiredBodyRejected() {
  var r = b.router.create();
  var handlerRan = false;
  r.post("/items", { body: s.object({ name: s.string() }) }, function (req, res) {
    handlerRan = true;
    res.writeHead(200); res.end("created");
  });

  // No body was parsed onto the request (req.body === undefined).
  var res = _res();
  await r.handle(_req("POST", "/items"), res);
  check("missing required body → 400", res.statusCode === 400);
  check("missing required body → handler did not run", handlerRan === false);
  check("missing required body → validation error names the body location",
    /"where":"body"/.test(res._body));
}

async function testValidBodyAccepted() {
  var r = b.router.create();
  var seen = null;
  r.post("/items", { body: s.object({ name: s.string() }) }, function (req, res) {
    seen = req.body;
    res.writeHead(200); res.end("created");
  });

  var req = _req("POST", "/items");
  req.body = { name: "widget" };
  var res = _res();
  await r.handle(req, res);
  check("valid body → 200", res.statusCode === 200);
  check("valid body → handler sees parsed body", seen && seen.name === "widget");
}

async function testOptionalBodyAbsentAccepted() {
  // An explicitly-optional body schema must still pass when no body is sent —
  // the fix validates, it does not require a body unconditionally.
  var r = b.router.create();
  var handlerRan = false;
  r.post("/items", { body: s.object({ name: s.string() }).optional() }, function (req, res) {
    handlerRan = true;
    res.writeHead(200); res.end("ok");
  });

  var res = _res();
  await r.handle(_req("POST", "/items"), res);
  check("optional body absent → 200", res.statusCode === 200 && handlerRan === true);
}

// An expression tree: every node is one of three operator objects or a number,
// and the operands recurse. Each union option descends into `left` before it
// can fail, so a union that re-validates the same operand once per option does
// options^depth work on a body a few hundred bytes long.
function _exprSchema() {
  var Expr;
  function bin(op) {
    return s.object({
      op:    s.literal(op),
      left:  s.lazy(function () { return Expr; }),
      right: s.lazy(function () { return Expr; }),
    });
  }
  Expr = s.union([bin("+"), bin("-"), bin("*"), s.number()]);
  return Expr;
}

// A tree node whose two variants share ONE lazy reference and put the recursive
// key first, so a variant cannot fail on its tag before descending.
function _treeSchema() {
  var Node;
  var child = s.lazy(function () { return Node; });
  Node = s.union([
    s.object({ child: child.optional(), kind: s.literal("folder") }),
    s.object({ child: child.optional(), kind: s.literal("link") }),
  ]);
  return Node;
}

function _exprBody(depth, op, leaf) {
  var x = leaf;
  for (var i = 0; i < depth; i += 1) x = { op: op, left: x, right: 1 };
  return x;
}

function _treeBody(depth, leafKind) {
  var x = { kind: leafKind };
  for (var i = 0; i < depth; i += 1) x = { child: x, kind: "link" };
  return x;
}

async function testRecursiveUnionBodyCostFollowsInputSize() {
  var Expr = _exprSchema();
  var Tree = _treeSchema();
  var shapes = [
    { label: "expression tree, valid, every node the last union option",
      run: function (d) { Expr.safeParse(_exprBody(d, "*", 1)); } },
    { label: "expression tree, invalid leaf",
      run: function (d) { Expr.safeParse(_exprBody(d, "+", "x")); } },
    { label: "tree node sharing one lazy reference, invalid leaf",
      run: function (d) { Tree.safeParse(_treeBody(d, "file")); } },
    { label: "tree node sharing one lazy reference, valid, every node the second union option",
      run: function (d) { Tree.safeParse(_treeBody(d, "link")); } },
  ];
  var blownUp = [];
  shapes.forEach(function (shape) {
    var grows = helpers.looksSuperlinear(shape.run, { small: 8, large: 16, threshold: 8, floorMs: 5 });
    if (grows) blownUp.push(shape.label);
  });
  check("safeSchema: a recursive union's cost follows the body's depth, not options^depth" +
        (blownUp.length ? " (grew: " + blownUp.join("; ") + ")" : ""), blownUp.length === 0);
  if (blownUp.length) return;

  // Four times the depth: linear work grows about 4x, work quadratic in the
  // depth about 16x.
  var quadratic = [];
  shapes.forEach(function (shape) {
    var grows = helpers.looksSuperlinear(shape.run, { small: 50, large: 200, threshold: 8, floorMs: 5 });
    if (grows) quadratic.push(shape.label);
  });
  check("safeSchema: a recursive union's cost is linear in the body's depth" +
        (quadratic.length ? " (grew: " + quadratic.join("; ") + ")" : ""), quadratic.length === 0);
  if (quadratic.length) return;

  var r = b.router.create();
  var seen = null;
  r.post("/calc", { body: Expr }, function (req, res) { seen = req.body; res.writeHead(200); res.end("ok"); });

  var validReq = _req("POST", "/calc");
  validReq.body = _exprBody(90, "*", 1);
  var validRes = _res();
  await r.handle(validReq, validRes);
  check("router: a 90-level valid expression body is accepted", validRes.statusCode === 200 && seen !== null,
        validRes.statusCode);

  var badReq = _req("POST", "/calc");
  badReq.body = _exprBody(90, "+", "x");
  var badRes = _res();
  await r.handle(badReq, badRes);
  check("router: a 90-level expression body with a bad leaf is refused with 400", badRes.statusCode === 400,
        badRes.statusCode);
  check("router: the refusal body stays small (" + badRes._body.length + " bytes)",
        badRes._body.length < 64 * 1024, badRes._body.length);

  var parsed = Expr.safeParse(_exprBody(90, "+", "x"));
  var deepest = parsed.errors.reduce(function (m, e) { return Math.max(m, e.path.length); }, 0);
  check("safeSchema: the issue list is bounded (" + parsed.errors.length + " issues)",
        parsed.errors.length <= 256, parsed.errors.length);
  check("safeSchema: the bounded issue list still reaches the failing leaf (deepest path " + deepest + ")",
        deepest >= 90, deepest);
}

async function run() {
  await testMissingRequiredBodyRejected();
  await testValidBodyAccepted();
  await testOptionalBodyAbsentAccepted();
  await testRecursiveUnionBodyCostFollowsInputSize();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK router-body-validation — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
