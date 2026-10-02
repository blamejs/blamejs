// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A comment block that names any of its primitive's error codes names all of
 * them.
 *
 * An operator reads the block to learn what to catch, and a partial list sends
 * them into production with a branch missing. `b.csp.build` named one of its
 * nine refusals, so `csp/header-injection`, `csp/unsafe-keyword` and
 * `csp/catch-all-source` reached nobody; `b.mail.crypto.smime.checkCert`
 * attributed the SHA-1 and short-RSA refusals to `mail-crypto/smime/bad-cert`
 * when they arrive as `refused-hash` and `rsa-too-small`.
 *
 * A block that names no code at all is a different question and is out of
 * scope: it documents nothing to be partial about.
 *
 * Scope boundary, stated rather than allowlisted: the block must sit above a
 * function that opens no further function. A code constructed inside a nested
 * function is thrown when THAT function runs — from a returned handle, a
 * listener, a worker callback — so attributing it to the primitive the block
 * describes would be wrong. `testTheScopeBoundaryIsNotSwallowingTheWork`
 * reports how many blocks the boundary holds back.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var ROOT = nodePath.join(__dirname, "..", "..");
var LIB  = nodePath.join(ROOT, "lib");

// An error code: two or more slash-separated lowercase segments.
var CODE_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\/[a-z0-9]+(?:-[a-z0-9]+)*){1,3}$/;

// A code reaches an error one of two ways: as the first argument of a
// `new <X>Error(`, or as the argument a shared validator takes right after the
// error CLASS it is to build. Keying the second on the class is what keeps
// `setHeader("Content-Type", "application/json")` out of the vocabulary.
var NEW_ERROR_RE = /new\s+[A-Za-z_$][A-Za-z0-9_$]*Error\(\s*(?:"([^"\n]+)"|'([^'\n]+)')/g;
var CLASS_THEN_CODE_RE = /[A-Za-z_$][A-Za-z0-9_$]*Error\s*,\s*(?:"([^"\n]+)"|'([^'\n]+)')/g;

var BACKTICK_RE = /`([^`\n]{1,160})`/g;
var BLOCK_RE    = /\/\*\*[\s\S]*?\*\//g;

function walk(dir, out) {
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (ent) {
    var full = nodePath.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === "vendor" || ent.name === "node_modules") return;
      walk(full, out);
      return;
    }
    if (ent.isFile() && /\.js$/.test(ent.name)) out.push(full);
  });
  return out;
}

// Comment blocks become same-length runs of spaces, so a code only MENTIONED in
// prose never counts as constructed and every line number stays put.
function stripBlocks(src) {
  return src.replace(BLOCK_RE, function (m) { return m.replace(/[^\n]/g, " "); });
}

function codesIn(text) {
  var out = {};
  var m;
  NEW_ERROR_RE.lastIndex = 0;
  while ((m = NEW_ERROR_RE.exec(text)) !== null) {
    var a = m[1] !== undefined ? m[1] : m[2];
    if (a.indexOf("/") !== -1) out[a] = true;
  }
  CLASS_THEN_CODE_RE.lastIndex = 0;
  while ((m = CLASS_THEN_CODE_RE.exec(text)) !== null) {
    var c = m[1] !== undefined ? m[1] : m[2];
    if (c.indexOf("/") !== -1) out[c] = true;
  }
  return out;
}

// A trailing slash means the literal is a PREFIX a builder completes, not a
// code: `"backup/"` names no refusal an operator can catch.
function isWholeCode(codeStr) {
  var last = codeStr.slice(codeStr.lastIndexOf("/") + 1);
  return last.length > 0;
}

function lineOf(src, index) { return src.slice(0, index).split("\n").length; }

// The body the block describes: from the end of the block to the first closing
// brace at column 0, which is where a top-level function ends.
//
// Returns null when the block does not sit above a function declaration. A
// block over `var SafeSqlError = frameworkError.defineMessageFirstClass(...)`
// describes an error CLASS, and reading on to the next `\n}` would collect the
// codes of whatever function follows it.
var OPENS_A_FUNCTION = /^\s*(?:async\s+)?function\s+[A-Za-z_$]/;

function bodyAfter(code, blockEnd) {
  var after = code.slice(blockEnd);
  if (!OPENS_A_FUNCTION.test(after)) return null;
  var end = after.search(/\n\}/);
  return end === -1 ? after : after.slice(0, end);
}

// Everything past the line that opens the function. The declaration itself is
// excluded so its own `function` keyword does not read as a nested one.
function pastDeclaration(body) {
  var at = body.search(/\{[ \t]*$/m);
  return at === -1 ? body : body.slice(at);
}

var FILES = walk(LIB, []);

// ---- The vocabulary: namespaces the tree really builds errors in. ----
var NAMESPACES = {};
var STRIPPED = {};
FILES.forEach(function (full) {
  var rel = nodePath.relative(ROOT, full).replace(/\\/g, "/");
  var code = stripBlocks(nodeFs.readFileSync(full, "utf8"));
  STRIPPED[rel] = code;
  Object.keys(codesIn(code)).forEach(function (c) { NAMESPACES[c.split("/")[0]] = true; });
});

// ---- Walk every @primitive block. ----
function collect() {
  var inScope = [];
  var heldBack = [];
  var notAFunction = 0;
  FILES.forEach(function (full) {
    var rel = nodePath.relative(ROOT, full).replace(/\\/g, "/");
    var src = nodeFs.readFileSync(full, "utf8");
    var code = STRIPPED[rel];
    var m;
    BLOCK_RE.lastIndex = 0;
    while ((m = BLOCK_RE.exec(src)) !== null) {
      var blk = m[0];
      if (blk.indexOf("@primitive") === -1) continue;

      var documented = {};
      var bm;
      BACKTICK_RE.lastIndex = 0;
      while ((bm = BACKTICK_RE.exec(blk)) !== null) {
        var inner = bm[1];
        if (!CODE_RE.test(inner)) continue;
        if (!NAMESPACES[inner.split("/")[0]]) continue;
        documented[inner] = true;
      }
      if (Object.keys(documented).length === 0) continue;

      var prim = (blk.match(/@primitive\s+(\S+)/) || [])[1] || "(unnamed)";
      var body = bodyAfter(code, m.index + blk.length);
      if (body === null) { notAFunction += 1; continue; }
      var entry = {
        file:       rel,
        line:       lineOf(src, m.index),
        prim:       prim,
        documented: Object.keys(documented).sort(),
      };
      if (/\bfunction\b/.test(pastDeclaration(body))) {
        heldBack.push(entry);
        continue;
      }
      entry.missing = Object.keys(codesIn(body))
        .filter(isWholeCode)
        .filter(function (c) { return !documented[c]; })
        .sort();
      inScope.push(entry);
    }
  });
  return { inScope: inScope, heldBack: heldBack, notAFunction: notAFunction };
}

var WALK = collect();

function testTheWalkReadTheTree() {
  var documenting = WALK.inScope.length + WALK.heldBack.length;
  check("lib/ was walked and the error vocabulary built",
        FILES.length >= 400 && Object.keys(NAMESPACES).length >= 100,
        FILES.length + " files, " + Object.keys(NAMESPACES).length + " namespaces");
  check("the walk found blocks that document error codes",
        documenting >= 100, documenting + " blocks name at least one code");
}

function testEveryDocumentedCodeListIsComplete() {
  var partial = WALK.inScope.filter(function (e) { return e.missing.length; });
  var lines = partial.map(function (e) {
    return e.file + ":" + e.line + " " + e.prim + " omits " + e.missing.join(" ");
  });
  check("every block that names an error code names all the codes its function throws" +
        (lines.length ? " (" + lines.slice(0, 8).join("; ") +
          (lines.length > 8 ? "; +" + (lines.length - 8) + " more" : "") + ")" : ""),
        lines.length === 0);
}

function testTheScopeBoundaryIsNotSwallowingTheWork() {
  // The boundary exists because a nested function's codes are not this
  // primitive's to throw. It is reported rather than silent: a boundary that
  // grew to hold back most of the tree would be a gate that checks nothing.
  var held = WALK.heldBack.length;
  var total = WALK.inScope.length + held + WALK.notAFunction;
  check("the gate reads the majority of the blocks that document codes",
        WALK.inScope.length > held,
        WALK.inScope.length + " read, " + held + " held back by the nested-function boundary, " +
        WALK.notAFunction + " over something that is not a function declaration, of " + total);
}

function testTheGateCanFail() {
  // A control, because every other assertion here is expected to pass: run the
  // same extractors over a fixture whose block omits a code its body throws.
  var fixture = [
    "/**",
    " * @primitive  b.fixture.only",
    " * Throws `fixture/documented` when the input is empty.",
    " */",
    "function only(x) {",
    "  if (!x) throw new FixtureError(\"fixture/documented\", \"empty\");",
    "  if (x < 0) throw new FixtureError(\"fixture/undocumented\", \"negative\");",
    "  return x;",
    "}",
    "",
  ].join("\n");
  var stripped = stripBlocks(fixture);
  var blockEnd = fixture.indexOf("*/") + 2;
  var body = bodyAfter(stripped, blockEnd);
  var thrown = Object.keys(codesIn(body)).sort();
  check("the extractor reads both codes out of a fixture body",
        thrown.join(",") === "fixture/documented,fixture/undocumented", thrown.join(","));
  check("the fixture body is in scope — it opens no nested function",
        !/\bfunction\b/.test(pastDeclaration(body)));
  var documented = { "fixture/documented": true };
  var missing = thrown.filter(function (c) { return !documented[c]; });
  check("the comparison reports the undocumented code",
        missing.length === 1 && missing[0] === "fixture/undocumented", missing.join(","));
}

async function run() {
  testTheWalkReadTheTree();
  testEveryDocumentedCodeListIsComplete();
  testTheScopeBoundaryIsNotSwallowingTheWork();
  testTheGateCanFail();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[operator-doc-error-codes] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
