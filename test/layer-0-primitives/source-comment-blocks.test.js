// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Source @module / @primitive comment-block gate.
 *
 * Same engine that runs in CI's `Wiki @module / @primitive comment-
 * block convention` job (`scripts/validate-source-comment-blocks.js`),
 * but wired into smoke as a Layer 0 check so the validator fires on
 * every `node test/smoke.js` invocation — not just when someone
 * remembers to invoke the standalone script.
 *
 * Catches the class of finding Codex / CI flagged on PRs #50 / #51 /
 * #52 / #53 / #54 (missing `@primitive` block, `@related` namespace
 * vs primitive reference, prose-too-short, `@example` parse error).
 */

var path     = require("node:path");
var validator = require(path.join(__dirname, "..", "..", "examples", "wiki", "lib",
                                  "source-comment-block-validator.js"));
var parser    = require(path.join(__dirname, "..", "..", "examples", "wiki", "lib",
                                  "source-doc-parser"));
var helpers  = require("../helpers");
var check    = helpers.check;

// Local opts-resolver — mirrors examples/wiki/lib/opts-resolver.js but
// resolves `b` through the in-tree framework instead of the wiki's npm
// `@blamejs/core` symlink. Wires the opts-undocumented check into the
// framework smoke gate so the class CI's wiki-e2e was the only catcher
// of (PR #58 v0.9.31 missed @opts blocks) fires pre-push.
function _buildLocalOptsResolver() {
  var b;
  try { b = require("../.."); }
  catch (_e) { return null; }
  function _resolveFn(signature) {
    var m = String(signature).match(/^\s*(?:<code>\s*)?b\.([a-zA-Z0-9_.]+)\s*\(/);
    if (!m) return null;
    var parts = m[1].split(".");
    var cur = b;
    for (var i = 0; i < parts.length; i += 1) {
      if (cur === null || cur === undefined) return null;
      cur = cur[parts[i]];
    }
    return typeof cur === "function" ? cur : null;
  }
  function _probe(fn) {
    if (typeof fn !== "function") return { ok: false, reason: "not-a-function" };
    var probeKey = "__opts_smoke_probe_" + Date.now() + "_" + Math.random().toString(36).slice(2);     // allow:math-random-noncrypto-jitter-sampling — probe-key uniqueness only
    var probeOpts = {}; probeOpts[probeKey] = true;
    var caught = null;
    try {
      var rv = fn(probeOpts);
      if (rv && typeof rv.then === "function") {
        rv.catch(function () { /* async validation; probe doesn't surface */ });
        return { ok: false, reason: "async-only-validation" };
      }
    } catch (e) { caught = e; }
    if (!caught) return { ok: false, reason: "no-throw" };
    var msg = caught.message || String(caught);
    var match = msg.match(/Allowed(?:\s+keys)?:\s*([^.]*)/i);
    if (!match) return { ok: false, reason: "no-allow-list-in-error" };
    var keys = match[1].split(",")
      .map(function (s) { return s.trim().replace(/[`'"]/g, ""); })
      .filter(Boolean);
    return { ok: true, allowed: keys };
  }
  return {
    resolve: function (signature) {
      var fn = _resolveFn(signature);
      if (!fn) return { ok: false, reason: "lib-fn-not-resolved" };
      return _probe(fn);
    },
  };
}

var optsResolver = _buildLocalOptsResolver();

// ---------------------------------------------------------------------------
// @related fixtures.
//
// Running the engine over lib/ and asserting "clean" says the tree is clean;
// it does not say the check can fail. The @related resolution accepted a
// wholly invented namespace for as long as nobody checked, because a
// reference it could not resolve fell through to a branch that allowed it.
// Each fixture below is a one-file tree the engine is run against, so every
// branch has a case that proves it fires and a case that proves it stays
// quiet.
// ---------------------------------------------------------------------------

var fs = require("node:fs");
var os = require("node:os");

var FIXTURE_SNAPSHOT = {
  version: 1,
  exports: {
    realNs:  { type: "object", members: { realFn: { type: "function", arity: 1 } } },
    undocNs: { type: "object", members: { someFn: { type: "function", arity: 1 } } },
    nested:  { type: "object", members: { ns: { type: "object", members: {} } } },
  },
};

function _fixtureModule(ns, title) {
  return [
    "/**",
    " * @module b." + ns,
    " * @nav    Fixtures",
    " * @title  " + title,
    " *",
    " * @intro",
    " *   A fixture namespace used to drive the @related resolution branches.",
    " *",
    " * @card",
    " *   A fixture namespace used to drive the @related resolution branches.",
    " */",
    "",
  ].join("\n");
}

function _fixturePrimitive(sig, related) {
  return [
    "/**",
    " * @primitive b." + sig,
    " * @signature b." + sig + "(value)",
    " * @since     0.1.0",
    " * @status    stable",
    " * @related   " + related,
    " *",
    " * A fixture primitive that exists only to carry a @related reference.",
    " *",
    " * @example",
    " *   var out = b." + sig + "(1);",
    " */",
    "",
  ].join("\n");
}

// Build a temp tree: <root>/api-snapshot.json + <root>/lib/<files>, run the
// engine over <root>/lib, and answer the cross-ref findings alone.
function _crossRefFindings(files, opts) {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-scb-fx-"));
  try {
    if (!(opts && opts.omitSnapshot)) {
      fs.writeFileSync(path.join(root, "api-snapshot.json"),
        JSON.stringify(opts && opts.snapshot ? opts.snapshot : FIXTURE_SNAPSHOT));
    }
    var libDir = path.join(root, "lib");
    fs.mkdirSync(libDir);
    Object.keys(files).forEach(function (name) {
      fs.writeFileSync(path.join(libDir, name), files[name]);
    });
    var found = validator.validate({ libDir: libDir, parser: parser, curationPages: [] });
    return found.filter(function (f) { return f.kind === "cross-ref"; });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function _oneFile(related, extra) {
  var src = _fixtureModule("realNs", "Real") +
            _fixturePrimitive("realNs.realFn", related) +
            "function realFn(value) { return value; }\n" +
            "module.exports = { realFn: realFn };\n";
  return Object.assign({ "real-ns.js": src }, extra || {});
}

function testRelatedResolutionBranches() {
  var cases = [
    { label: "a reference to a namespace the framework does not export is refused",
      related: "b.totallyBogus.nope", fires: /exports nothing by that name/ },
    { label: "a reference that does not start with b. is refused",
      related: "Money.prototype.toString", fires: /does not start with/ },
    { label: "a reference into a documented namespace that has no such member is refused",
      related: "b.realNs.missingFn", fires: /is documented but this primitive isn't there/ },
    { label: "a reference into an exported but undocumented namespace is allowed",
      related: "b.undocNs.someFn", fires: null },
    { label: "a reference to a documented primitive is allowed",
      related: "b.realNs.realFn", fires: null },
    { label: "a bare reference to a documented namespace is allowed",
      related: "b.realNs", fires: null },
  ];
  cases.forEach(function (c) {
    var found = _crossRefFindings(_oneFile(c.related));
    if (c.fires) {
      check("@related: " + c.label,
        found.length === 1 && c.fires.test(found[0].msg));
    } else {
      check("@related: " + c.label, found.length === 0);
    }
  });

  // A nested @module namespace resolves as a bare reference the same way a
  // single-segment one does.
  var nestedFiles = _oneFile("b.nested.ns", {
    "nested-ns.js": _fixtureModule("nested.ns", "Nested") +
      _fixturePrimitive("nested.ns.someFn", "b.realNs.realFn") +
      "function someFn(value) { return value; }\n" +
      "module.exports = { someFn: someFn };\n",
  });
  check("@related: a bare reference to a nested @module namespace is allowed",
    _crossRefFindings(nestedFiles).length === 0);

  // Without the export list the engine cannot answer the question, so it
  // refuses to run rather than passing everything.
  var threw = null;
  try { _crossRefFindings(_oneFile("b.realNs.realFn"), { omitSnapshot: true }); }
  catch (e) { threw = e; }
  check("@related: the gate refuses to run without the export list",
    threw !== null && /api-snapshot\.json/.test(threw.message));
}

// The rule that keeps a tagged block is what stops the comment stripper from
// deleting a primitive's documentation. It asked only whether SOME line starts
// with an at-sign word, never which word, so any invented tag preserved
// arbitrary narrative in lib/ — an escape hatch from the gate that exists to
// keep that narrative out.
function testOnlyARecognizedTagKeepsABlock() {
  var stripper = require(path.join(__dirname, "..", "..", "scripts",
                                   "strip-lib-comments.js"));
  function kept(text) {
    return stripper.isKept(text, text, { start: 0, end: text.length }, [], 0);
  }

  var NARRATIVE = " * This was added after the second drift audit; it is kept here\n" +
                  " * so the next reader knows how we got to this shape.\n";

  check("a block carrying a recognized wiki tag is kept",
    kept("/**\n * @primitive b.thing.do\n" + NARRATIVE + " */") === "jsdoc-tagged");
  check("an invented tag does NOT keep a block of narrative",
    kept("/**\n * @note\n" + NARRATIVE + " */") !== "jsdoc-tagged");
  check("nor does a single-letter tag",
    kept("/**\n * @x\n" + NARRATIVE + " */") !== "jsdoc-tagged");
  check("and the same narrative with no tag is still not kept",
    kept("/**\n" + NARRATIVE + " */") !== "jsdoc-tagged");

  // Every tag the tree actually uses has to stay recognized, or the stripper
  // would start proposing the deletion of real documentation.
  ["module", "primitive", "signature", "since", "status", "related", "opts",
   "example", "exampleFile", "intro", "card", "section", "nav", "title",
   "order", "slug", "featured", "compliance", "method", "abiTemplate",
   "concept", "param", "returns", "path", "generated"].forEach(function (tag) {
    check("@" + tag + " keeps its block",
      kept("/**\n * @" + tag + " x\n" + NARRATIVE + " */") === "jsdoc-tagged");
  });
}

async function run() {
  testRelatedResolutionBranches();
  testOnlyARecognizedTagKeepsABlock();
  var libDir = path.join(__dirname, "..", "..", "lib");
  var findings = validator.validate({
    libDir:       libDir,
    parser:       parser,
    curationPages: [],          // wiki-only concept; framework smoke doesn't seed pages
    optsResolver: optsResolver, // enables the opts-undocumented probe in smoke
  });

  if (findings.length > 0) {
    // Surface every finding so smoke output names exactly what to fix.
    for (var i = 0; i < findings.length; i += 1) {
      var f = findings[i];
      var label = "source-comment-blocks: " +
                  (f.kind || "finding") + " — " +
                  (f.file ? f.file : "<unknown file>") +
                  (f.primitive ? " :: " + f.primitive : "") +
                  ": " + (f.msg || "");
      check(label, false);
    }
    return;
  }
  check("source-comment-blocks: validator clean (no findings)", true);
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
