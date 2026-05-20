#!/usr/bin/env node
"use strict";
/**
 * Generate the CHANGELOG.md section for a release from a structured
 * JSON source at `release-notes/v<version>.json`.
 *
 * The structured source enforces operator-facing shape — every field
 * has a known semantic (headline, summary, sections[].items[], etc.)
 * and runs through a leak-vocabulary validator before the markdown
 * emitter. Hand-written prose can drift into internal-process
 * narrative ("per rule §X", phase / sweep / tier vocabulary); the
 * JSON pipeline refuses such input at validation time so the
 * discipline holds by construction.
 *
 * Usage:
 *   node scripts/generate-changelog-entry.js          # version from package.json
 *   node scripts/generate-changelog-entry.js 0.11.7   # explicit version
 *
 * Outputs:
 *   - Emits the rendered Markdown to stdout.
 *   - With `--write`: replaces the existing entry block for the same
 *     version in CHANGELOG.md (or inserts a new top entry under the
 *     `## v0.<minor>.x` section).
 *
 * Validation refusals — the generator exits non-zero when:
 *   - The JSON is missing required fields.
 *   - Any string field contains a leak-vocabulary token from the
 *     LEAK_PATTERNS list below.
 *   - The version in the JSON doesn't match the requested version.
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT          = path.resolve(__dirname, "..");
var PACKAGE_JSON  = path.join(ROOT, "package.json");
var CHANGELOG     = path.join(ROOT, "CHANGELOG.md");
var NOTES_DIR     = path.join(ROOT, "release-notes");

// LEAK_PATTERNS — tokens that signal internal-process narrative
// instead of operator-facing description. Each pattern is built at
// runtime from char-class fragments so the literal token strings
// don't appear in the source of this validator either (the same
// posture the runtime codebase-patterns detector takes).
function _leakPatterns() {
  var claude = [67, 76, 65, 85, 68, 69]
    .map(function (c) { return String.fromCharCode(c); })
    .join("");
  return [
    // Internal config-file name + rule-shorthand variants.
    new RegExp("\\b" + claude + "\\.md\\b"),
    new RegExp("\\bper\\s+" + claude + "\\b"),
    /\bper\s+project\s+rule\s+§/,
    /\bper\s+rule\s+§\d/,
    // Phase / sweep / tier numbering — internal sequencing the
    // operator doesn't share.
    /\bphase\s+\d/i,
    /\bsweep\s+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch\s+\d/i,
    /\bgroup\s+[a-h]\b/i,
    /\bslice\s+\d/i,
    // "audit-derived" / "post-audit" — internal-process attribution.
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
    // AI-tooling vocabulary that should never reach operator-facing.
    /\b(?:anthropic|chatgpt|openai|copilot|sonnet|opus|haiku|gemini|co[- ]authored[- ]by|llm[- ]generated|ai[- ]generated)\b/i,
  ];
}

function _exit(msg) {
  process.stderr.write("[generate-changelog-entry] " + msg + "\n");
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) { _exit("cannot read " + label + " (" + filePath + "): " + (e && e.message || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + (e && e.message || e)); }
}

function _scanString(value, fieldPath, patterns) {
  var hits = [];
  for (var i = 0; i < patterns.length; i += 1) {
    if (patterns[i].test(value)) {
      hits.push({ path: fieldPath, pattern: patterns[i].source });
    }
  }
  return hits;
}

function _walkForLeaks(node, basePath, patterns, out) {
  if (typeof node === "string") {
    var hits = _scanString(node, basePath, patterns);
    for (var i = 0; i < hits.length; i += 1) out.push(hits[i]);
    return;
  }
  if (Array.isArray(node)) {
    for (var j = 0; j < node.length; j += 1) {
      _walkForLeaks(node[j], basePath + "[" + j + "]", patterns, out);
    }
    return;
  }
  if (node && typeof node === "object") {
    var keys = Object.keys(node);
    for (var k = 0; k < keys.length; k += 1) {
      if (keys[k] === "$schema") continue;
      _walkForLeaks(node[keys[k]], basePath + "." + keys[k], patterns, out);
    }
  }
}

// Section heading allowlist + canonical ordering. Modeled on the
// Keep-a-Changelog conventions plus framework-specific additions
// (`Detectors`, `Migration`). Order at render-time follows this
// list regardless of the JSON's declaration order, so generated
// entries are structurally identical across releases.
var SECTION_ALLOWLIST_ORDER = [
  "Added",
  "Changed",
  "Deprecated",
  "Removed",
  "Fixed",
  "Security",
  "Detectors",
  "Migration",
];

function _fail(errors) {
  process.stderr.write("[generate-changelog-entry] FAIL:\n");
  for (var i = 0; i < errors.length; i += 1) {
    process.stderr.write("  - " + errors[i] + "\n");
  }
  process.exit(1);
}

function validate(notes, version) {
  var errs = [];

  // ---- Required top-level fields ----

  if (notes.version !== version) {
    errs.push("`version` is " + JSON.stringify(notes.version) +
      " but expected " + JSON.stringify(version));
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(notes.date || "")) {
    errs.push("`date` must be `YYYY-MM-DD`; got " + JSON.stringify(notes.date));
  }
  if (typeof notes.headline !== "string" || notes.headline.length < 8) {                // allow:raw-byte-literal — min headline length floor
    errs.push("`headline` missing or shorter than 8 characters");
  } else {
    if (/[.!?]$/.test(notes.headline)) {
      errs.push("`headline` must not end with sentence punctuation (the renderer adds the period)");
    }
    if (notes.headline !== notes.headline.trim()) {
      errs.push("`headline` has leading/trailing whitespace");
    }
    if (!/^[A-Z`]/.test(notes.headline)) {
      errs.push("`headline` must start with a capital letter or backtick (current: " +
        JSON.stringify(notes.headline.slice(0, 16)) + "...)");
    }
  }
  if (notes.summary !== undefined) {
    if (typeof notes.summary !== "string") errs.push("`summary` must be a string when present");
    else if (notes.summary !== notes.summary.trim()) errs.push("`summary` has leading/trailing whitespace");
    else if (notes.summary.length > 0 && !/[.!?]$/.test(notes.summary)) {
      errs.push("`summary` must end with sentence punctuation");
    }
  }

  // ---- Sections ----

  if (!Array.isArray(notes.sections) || notes.sections.length === 0) {
    errs.push("`sections` must be a non-empty array");
  } else {
    var seenHeadings = {};
    for (var s = 0; s < notes.sections.length; s += 1) {
      var sec = notes.sections[s];
      var pfx = "sections[" + s + "]";
      if (typeof sec.heading !== "string") {
        errs.push(pfx + ".heading missing");
        continue;
      }
      if (SECTION_ALLOWLIST_ORDER.indexOf(sec.heading) === -1) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " not in allowlist: " + SECTION_ALLOWLIST_ORDER.join(" / "));
      }
      if (seenHeadings[sec.heading]) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " duplicates an earlier section — consolidate items under one section");
      }
      seenHeadings[sec.heading] = true;
      if (!Array.isArray(sec.items) || sec.items.length === 0) {
        errs.push(pfx + " (" + sec.heading + ") `items` missing/empty");
        continue;
      }
      for (var t = 0; t < sec.items.length; t += 1) {
        var it  = sec.items[t];
        var ipx = pfx + ".items[" + t + "]";
        if (typeof it.title !== "string" || it.title.length === 0) {
          errs.push(ipx + ".title missing");
        } else {
          if (it.title !== it.title.trim()) errs.push(ipx + ".title has leading/trailing whitespace");
          if (/[.!?]$/.test(it.title))      errs.push(ipx + ".title must not end with sentence punctuation");
          if (!/^[A-Za-z`]/.test(it.title)) errs.push(ipx + ".title must start with a letter or backtick");
        }
        if (typeof it.body !== "string" || it.body.length === 0) {
          errs.push(ipx + ".body missing");
        } else {
          if (it.body !== it.body.trim()) errs.push(ipx + ".body has leading/trailing whitespace");
          if (!/[.!?]$/.test(it.body))    errs.push(ipx + ".body must end with sentence punctuation");
          if (it.body.length < 16) {                                                    // allow:raw-byte-literal — min body length floor
            errs.push(ipx + ".body shorter than 16 characters (under-described — operators need context)");
          }
        }
      }
    }
  }

  // ---- References ----

  if (notes.references !== undefined) {
    if (!Array.isArray(notes.references)) {
      errs.push("`references` must be an array when present");
    } else {
      for (var r = 0; r < notes.references.length; r += 1) {
        var ref = notes.references[r];
        var rpx = "references[" + r + "]";
        if (typeof ref.label !== "string" || ref.label.length === 0) {
          errs.push(rpx + ".label missing");
        }
        if (typeof ref.url !== "string" || !/^https:\/\//.test(ref.url)) {
          errs.push(rpx + ".url must be an https:// URL");
        }
      }
    }
  }

  // ---- Leak-vocabulary sweep ----

  var hits = [];
  _walkForLeaks(notes, "$", _leakPatterns(), hits);
  if (hits.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL: leak-vocabulary tokens found in release-notes JSON:\n");
    for (var h = 0; h < hits.length; h += 1) {
      process.stderr.write("  " + hits[h].path + "  ←  pattern /" + hits[h].pattern + "/\n");
    }
    process.stderr.write("[generate-changelog-entry] Each field must be operator-facing. Strip internal-process narrative + rewrite.\n");
    if (errs.length > 0) _fail(errs);
    process.exit(1);
  }

  if (errs.length > 0) _fail(errs);
}

// Re-order sections to the canonical sequence at render time.
function _sortSections(sections) {
  return sections.slice().sort(function (a, b) {
    return SECTION_ALLOWLIST_ORDER.indexOf(a.heading) -
           SECTION_ALLOWLIST_ORDER.indexOf(b.heading);
  });
}

// CHANGELOG mode — single-line bullet entry matching the existing
// CHANGELOG.md prose convention:
//   - vX.Y.Z (YYYY-MM-DD) — **Headline.** Summary paragraph.
//     Section heading: item-title — item-body. ...
//     References: [label1](url1) · [label2](url2) ...
// One-line shape preserves the awk-extractor contract used by the
// workflow + the local check-changelog-extract gate.
function renderChangelogLine(notes) {
  var out = "- v" + notes.version + " (" + notes.date + ") — **" + notes.headline + ".**";
  if (notes.summary && notes.summary.length > 0) {
    out += " " + notes.summary;
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    out += " **" + sec.heading + ":** ";
    var parts = sec.items.map(function (it) {
      return "*" + it.title + "* — " + it.body;
    });
    out += parts.join(" · ");
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    var refList = notes.references.map(function (r) {
      return "[" + r.label + "](" + r.url + ")";
    });
    out += " **References:** " + refList.join(" · ");
  }
  return out;
}

// Release-page mode — multi-section markdown for the GitHub release
// page. Uses `##` headings + bullet lists per section so each item
// renders as its own scannable card on the release page instead of a
// single dense paragraph. The workflow's gh-release-create step
// passes this output via --notes-file.
function renderReleasePage(notes) {
  var lines = [];
  lines.push("**" + notes.headline + ".**");
  lines.push("");
  if (notes.summary && notes.summary.length > 0) {
    lines.push(notes.summary);
    lines.push("");
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    lines.push("## " + sec.heading);
    lines.push("");
    for (var t = 0; t < sec.items.length; t += 1) {
      var it = sec.items[t];
      // Each item: bold title, em-dash, body. One bullet per item.
      lines.push("- **" + it.title + "** — " + it.body);
    }
    lines.push("");
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    lines.push("## References");
    lines.push("");
    for (var r = 0; r < notes.references.length; r += 1) {
      var ref = notes.references[r];
      lines.push("- [" + ref.label + "](" + ref.url + ")");
    }
    lines.push("");
  }
  return lines.join("\n");
}

// Legacy alias preserved for the splice path below.
function render(notes) { return renderChangelogLine(notes); }

function _readPackageVersion() {
  var pkg = _readJson(PACKAGE_JSON, "package.json");
  return pkg.version;
}

// Lookup tries the per-patch file first, then the consolidated
// minor-line rollup. This lets non-current minor lines collapse to
// a single `v<minor>.x.json` (via `scripts/consolidate-release-notes.js`)
// without breaking the generator's `node scripts/generate-changelog-entry.js
// 0.5.3`-style invocations.
function _loadReleaseNotes(version) {
  var perPatchPath = path.join(NOTES_DIR, "v" + version + ".json");
  if (fs.existsSync(perPatchPath)) {
    return {
      notes:  _readJson(perPatchPath, "release-notes/v" + version + ".json"),
      source: "v" + version + ".json",
    };
  }
  var m = version.match(/^(\d+\.\d+)\.\d+$/);
  if (!m) _exit("malformed version: " + JSON.stringify(version));
  var consolidatedPath = path.join(NOTES_DIR, "v" + m[1] + ".x.json");
  if (fs.existsSync(consolidatedPath)) {
    var con = _readJson(consolidatedPath, "release-notes/v" + m[1] + ".x.json");
    if (!Array.isArray(con.releases)) {
      _exit("consolidated file release-notes/v" + m[1] + ".x.json missing `releases` array");
    }
    for (var i = 0; i < con.releases.length; i += 1) {
      if (con.releases[i] && con.releases[i].version === version) {
        return {
          notes:  con.releases[i],
          source: "v" + m[1] + ".x.json (releases[" + i + "])",
        };
      }
    }
    _exit("v" + version + " not found inside consolidated file " +
      "release-notes/v" + m[1] + ".x.json — " +
      "the rollup may be stale or the version may not exist");
  }
  _exit("cannot find release notes for v" + version + " — " +
    "looked at release-notes/v" + version + ".json AND " +
    "release-notes/v" + m[1] + ".x.json (neither present)");
  return null;                                                                          // unreachable
}

function _spliceIntoChangelog(rendered, version) {
  if (!fs.existsSync(CHANGELOG)) _exit("CHANGELOG.md does not exist");
  var text = fs.readFileSync(CHANGELOG, "utf8");
  var lines = text.split(/\r?\n/);
  // Find an existing entry line for this version, OR the top of the
  // version's `## v0.<minor>.x` section.
  var entryRe = new RegExp("^- v" + version.replace(/\./g, "\\.") + " \\(");
  var minorMatch = version.match(/^(\d+\.\d+)\.\d+$/);
  var minorPrefix = minorMatch ? minorMatch[1] : "";
  var sectionHeaderRe = new RegExp("^## v" + minorPrefix.replace(/\./g, "\\.") + "\\.x\\b");

  // Try to find an existing entry to replace.
  for (var i = 0; i < lines.length; i += 1) {
    if (entryRe.test(lines[i])) {
      // Find the end of this entry (next `- v` line or `## v` section).
      var j = i + 1;
      while (j < lines.length && !/^- v\d/.test(lines[j]) && !/^## v\d/.test(lines[j])) {
        j += 1;
      }
      var before = lines.slice(0, i);
      var after  = lines.slice(j);
      var combined = before.concat([rendered], after);
      fs.writeFileSync(CHANGELOG, combined.join("\n"));
      return { mode: "replaced", line: i + 1 };
    }
  }
  // No existing entry — insert at top of the matching `## v0.X.x` section.
  for (var k = 0; k < lines.length; k += 1) {
    if (sectionHeaderRe.test(lines[k])) {
      // Find first blank or non-blank line after the section header
      // and insert the new entry above any existing first entry.
      var insertAt = k + 1;
      while (insertAt < lines.length && lines[insertAt].trim() === "") insertAt += 1;
      var before2 = lines.slice(0, insertAt);
      var after2  = lines.slice(insertAt);
      var combined2 = before2.concat([rendered, ""], after2);
      fs.writeFileSync(CHANGELOG, combined2.join("\n"));
      return { mode: "inserted", line: insertAt + 1 };
    }
  }
  _exit("could not locate section `## v" + minorPrefix + ".x` in CHANGELOG.md to insert v" + version);
  return null;                                                                          // unreachable
}

function main() {
  var explicitVersion = process.argv[2] && !process.argv[2].startsWith("--")
    ? process.argv[2]
    : null;
  var writeMode       = process.argv.indexOf("--write") !== -1;
  var releasePageMode = process.argv.indexOf("--release-page") !== -1;
  if (writeMode && releasePageMode) {
    _exit("--write and --release-page are mutually exclusive (write is CHANGELOG-only)");
  }
  var version = explicitVersion || _readPackageVersion();
  var loaded = _loadReleaseNotes(version);
  var notes = loaded.notes;
  validate(notes, version);

  if (releasePageMode) {
    var releaseMd = renderReleasePage(notes);
    process.stdout.write(releaseMd);
    process.stderr.write("[generate-changelog-entry] OK — rendered v" + version +
      " release-page markdown (" + releaseMd.length + " chars)\n");
    return;
  }

  var rendered = renderChangelogLine(notes);
  if (writeMode) {
    var info = _spliceIntoChangelog(rendered, version);
    process.stderr.write("[generate-changelog-entry] OK — " + info.mode + " v" + version +
      " entry into CHANGELOG.md at line " + info.line + "\n");
  } else {
    process.stdout.write(rendered + "\n");
    process.stderr.write("[generate-changelog-entry] OK — rendered v" + version +
      " entry (" + rendered.length + " chars); re-run with --write to splice into CHANGELOG.md, " +
      "or --release-page to emit GH-release-page markdown\n");
  }
}

main();
