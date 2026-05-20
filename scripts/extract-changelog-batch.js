#!/usr/bin/env node
"use strict";
/**
 * One-shot prep tool for the historical-CHANGELOG → structured-JSON
 * backfill. Splits `CHANGELOG.md` into per-version blob files under
 * `.extract-staging/v<version>.md`, one per entry. A parallel agent
 * fan-out then converts each blob into the structured shape under
 * `release-notes/v<version>.json` (and the generator validates each
 * output against the section allowlist + leak-vocabulary patterns
 * + title/body format).
 *
 * Output:
 *   .extract-staging/v0.11.7.md
 *   .extract-staging/v0.11.6.md
 *   ...
 *   .extract-staging/_manifest.json   — list of {version, path,
 *                                       lines, alreadyStructured} for
 *                                       the orchestrator to dispatch.
 *
 * Skips versions that already have a `release-notes/v<version>.json`
 * (the manifest tracks them as `alreadyStructured: true` so the
 * orchestrator can skip re-running an extraction).
 *
 * Usage:
 *   node scripts/extract-changelog-batch.js
 *
 * Idempotent: re-running overwrites the staging directory cleanly.
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT       = path.resolve(__dirname, "..");
var CHANGELOG  = path.join(ROOT, "CHANGELOG.md");
var STAGING    = path.join(ROOT, ".extract-staging");
var NOTES_DIR  = path.join(ROOT, "release-notes");

function _exit(msg) {
  process.stderr.write("[extract-changelog-batch] " + msg + "\n");
  process.exit(1);
}

function main() {
  if (!fs.existsSync(CHANGELOG)) _exit("CHANGELOG.md not found");
  var text = fs.readFileSync(CHANGELOG, "utf8");
  var lines = text.split(/\r?\n/);

  // Find every entry. Two shapes ship historically:
  //   - vX.Y.Z (YYYY-MM-DD) — ...           (current convention)
  //   - **X.Y.Z** (YYYY-MM-DD) — ...        (pre-v0.8.38 convention)
  // Each entry's body spans to the next entry-start line OR the next
  // `## v0.X.x` section break.
  var entryRe   = /^- (?:v|\*\*)(\d+\.\d+\.\d+)(?:\*\*)? \((\d{4}-\d{2}-\d{2})\) — /;
  var sectionRe = /^## v\d/;
  var entries = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var m = lines[i].match(entryRe);
    if (m) {
      if (current) entries.push(current);
      current = { version: m[1], date: m[2], startLine: i + 1, body: [lines[i]] };
      continue;
    }
    if (sectionRe.test(lines[i])) {
      if (current) { entries.push(current); current = null; }
      continue;
    }
    if (current) current.body.push(lines[i]);
  }
  if (current) entries.push(current);

  // Reset staging dir (idempotent).
  if (fs.existsSync(STAGING)) fs.rmSync(STAGING, { recursive: true, force: true });
  fs.mkdirSync(STAGING, { recursive: true });

  var manifest = [];
  for (var j = 0; j < entries.length; j += 1) {
    var e = entries[j];
    var jsonPath = path.join(NOTES_DIR, "v" + e.version + ".json");
    var alreadyStructured = fs.existsSync(jsonPath);
    var blobPath = path.join(STAGING, "v" + e.version + ".md");
    // Trim trailing blank lines so the blob is tight.
    var bodyLines = e.body.slice();
    while (bodyLines.length > 0 && bodyLines[bodyLines.length - 1].trim() === "") {
      bodyLines.pop();
    }
    var blob = bodyLines.join("\n") + "\n";
    fs.writeFileSync(blobPath, blob);
    manifest.push({
      version:           e.version,
      date:              e.date,
      lines:             bodyLines.length,
      bytes:             blob.length,
      blobPath:          path.relative(ROOT, blobPath).replace(/\\/g, "/"),
      jsonPath:          path.relative(ROOT, jsonPath).replace(/\\/g, "/"),
      alreadyStructured: alreadyStructured,
    });
  }

  fs.writeFileSync(path.join(STAGING, "_manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n");

  var todo = manifest.filter(function (m) { return !m.alreadyStructured; });
  var done = manifest.length - todo.length;
  process.stderr.write("[extract-changelog-batch] " + entries.length +
    " entries (" + done + " already structured, " + todo.length + " to extract)\n");
  process.stderr.write("[extract-changelog-batch] staging dir: " + path.relative(ROOT, STAGING) + "/\n");
  process.stderr.write("[extract-changelog-batch] manifest: .extract-staging/_manifest.json\n");
}

main();
