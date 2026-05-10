"use strict";
/**
 * Run every fuzz harness sequentially. Each is spawned in its own
 * child node process so a crash / process.exit(1) in one target
 * doesn't abort the rest. Used by `npm run fuzz` and as a fallback
 * when the GH Actions matrix isn't available.
 *
 * Per-target budget defaults to FUZZ_BUDGET_MS env (or 30s); per-run
 * total wall-clock budget defaults to FUZZ_TOTAL_BUDGET_MS (or N×budget).
 */

var path  = require("node:path");
var fs    = require("node:fs");
var spawn = require("node:child_process").spawnSync;

var dir   = __dirname;
var files = fs.readdirSync(dir)
  .filter(function (f) { return /\.fuzz\.js$/.test(f); })
  .map(function (f) { return path.join(dir, f); });

var budgetPer = parseInt(process.env.FUZZ_BUDGET_MS || "30000", 10);
var failed    = [];
var t0        = Date.now();

console.log("[fuzz-all] " + files.length + " harness(es), " + budgetPer + "ms each");

for (var i = 0; i < files.length; i++) {
  var name = path.basename(files[i]);
  console.log("\n[fuzz-all] starting " + name);
  var rv = spawn(process.execPath, [files[i]], {
    stdio: "inherit",
    env:   Object.assign({}, process.env, { FUZZ_BUDGET_MS: String(budgetPer) }),
  });
  if (rv.status !== 0) {
    failed.push({ file: name, status: rv.status });
  }
}

var elapsedMs = Date.now() - t0;
console.log("\n[fuzz-all] " + (files.length - failed.length) + "/" + files.length +
            " harness(es) clean — " + elapsedMs + "ms total");
if (failed.length > 0) {
  console.log("[fuzz-all] FAIL:");
  failed.forEach(function (f) {
    console.log("  - " + f.file + " (exit " + f.status + ")");
  });
  process.exit(1);
}
