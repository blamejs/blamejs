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

async function run() {
  var libDir = path.join(__dirname, "..", "..", "lib");
  var findings = validator.validate({
    libDir:       libDir,
    parser:       parser,
    curationPages: [],          // wiki-only concept; framework smoke doesn't seed pages
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
