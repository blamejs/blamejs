// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * GitHub-Actions-currency gate — the sibling of
 * `scripts/check-vendor-currency.js` for the CI/CD supply chain.
 *
 * Walks every `.github/workflows/*.yml`, reads each SHA-pinned
 * `uses: owner/repo[/subpath]@<sha>  # vX.Y.Z` reference, and asserts
 * the pinned version (from the trailing comment the pinact discipline
 * requires) matches the latest upstream release. A stale action
 * becomes a release blocker HERE — caught in the pre-merge gate suite
 * — instead of being surfaced after-the-fact by a Dependabot PR.
 *
 * Run locally:
 *   node scripts/check-actions-currency.js
 *   node scripts/check-actions-currency.js --json     // structured output
 *   node scripts/check-actions-currency.js --warn     // exit 0, print only
 *   node scripts/check-actions-currency.js --fix       // rewrite stale pins
 *                                                       // to the latest SHA +
 *                                                       // version comment,
 *                                                       // then exit 0
 *
 * `--fix` applies the same latest-release SHA the gate already resolves —
 * every `owner/repo[/subpath]@<sha>  # vX.Y.Z` reference to a stale action
 * is rewritten in place. Re-run without `--fix` (or let CI) to verify.
 *
 * Run in CI: the workflow passes GITHUB_TOKEN in the environment so the
 * GitHub API gives the authenticated 5000/hour budget instead of the
 * 60/hour unauthenticated per-IP limit. `stale` fails the gate;
 * transient `api-error` results are advisory unless
 * BLAMEJS_ACTIONS_CURRENCY_STRICT=1 converts them into hard fails too.
 *
 * Actions deliberately pinned to an older major (a new major the repo
 * has not adopted) carry a SPECIAL_MAP entry pinning the expected
 * major so the gate doesn't fight an intentional hold.
 */

var fs    = require("fs");
var path  = require("path");
var https = require("https");

var WORKFLOWS_DIR = path.join(__dirname, "..", ".github", "workflows");

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var DO_FIX     = process.argv.indexOf("--fix") !== -1;
var TIMEOUT_MS = 10000;

// Every human-readable line goes through here, and under `--json` it writes
// nothing. The JSON document is then the only thing on stdout, which is what a
// consumer piping this into a parser is entitled to assume.
//
// Writing the document and then continuing into the summary blocks put a
// trailing `[actions-currency] OK — …` line after the closing brace, so
// `JSON.parse` failed on the stream with "Unexpected non-whitespace character
// after JSON". The exit code is unchanged: a machine reader still wants a
// non-zero exit on stale.
var _out = process.stdout.write.bind(process.stdout);
function say(s) { if (!JSON_OUT) _out(s); }

// Per-action overrides. Keyed by "owner/repo".
//   { type: "hold-major", major: N, reason: "..." } — only flag stale
//        WITHIN the pinned major; a newer major is an intentional hold.
//   { type: "skip", reason: "..." }                 — never flag.
var SPECIAL_MAP = {
  // (none — every pinned action tracks upstream latest)
};

function _githubGet(apiPath) {
  return new Promise(function (resolve, reject) {
    var headers = {
      "User-Agent": "blamejs-actions-currency/1",
      "Accept":     "application/vnd.github+json",
    };
    // Authenticated requests get the 5000/hour budget. Both env names
    // are accepted (GITHUB_TOKEN in Actions, GH_TOKEN for local gh).
    var token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = "Bearer " + token;
    var req = https.get("https://api.github.com" + apiPath, { timeout: TIMEOUT_MS, headers: headers }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        if (res.statusCode !== 200) {
          return reject(new Error("github " + apiPath + " status " + res.statusCode));
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("github " + apiPath + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

async function _resolveSha(ownerRepo, ref) {
  // Resolve a tag to the COMMIT sha it points at — exactly what the
  // pinact discipline pins (`owner/repo@<commit-sha>  # tag`). The
  // commits endpoint dereferences annotated tags to their commit.
  var c = await _githubGet("/repos/" + ownerRepo + "/commits/" + encodeURIComponent(ref));
  if (!c || typeof c.sha !== "string") throw new Error("could not resolve sha for " + ownerRepo + "@" + ref);
  return c.sha;
}

// Fetch the supply-chain review material for a bump: the commit range
// between the pinned SHA and the new SHA (what actually changed), plus the
// release notes for the new tag. A human reviews this before trusting the
// pin — a compromised release surfaces here as an unexpected commit or an
// author/change that doesn't match the version bump.
async function _releaseChangelog(ownerRepo, oldSha, newTag, newSha) {
  var out = {
    compareUrl: "https://github.com/" + ownerRepo + "/compare/" + oldSha + "..." + newSha,
    commits: [], files: [], body: "", compareError: null,
  };
  try {
    var cmp = await _githubGet("/repos/" + ownerRepo + "/compare/" + oldSha + "..." + newSha);
    if (cmp && cmp.html_url) out.compareUrl = cmp.html_url;
    if (cmp && Array.isArray(cmp.commits)) {
      out.commits = cmp.commits.map(function (c) {
        var msg = ((c.commit && c.commit.message) || "").split("\n")[0];
        var who = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.name) || "?";
        return (c.sha || "").slice(0, 10) + "  " + who + "  " + msg;
      });
    }
    if (cmp && Array.isArray(cmp.files)) {
      // The actual code change per file. GitHub omits `.patch` for files
      // above its diff-size limit (large minified dist bundles) — those are
      // flagged so a reviewer knows to inspect them via the compare URL.
      out.files = cmp.files.map(function (f) {
        return {
          name: f.filename, status: f.status,
          add: f.additions, del: f.deletions,
          patch: typeof f.patch === "string" ? f.patch : null,
        };
      });
    }
  } catch (e) { out.compareError = (e && e.message) || String(e); }
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/tags/" + encodeURIComponent(newTag));
    if (rel && typeof rel.body === "string") out.body = rel.body;
  } catch (_e) { /* action ships tags without a GitHub Release body */ }
  return out;
}

async function _latestVersion(ownerRepo) {
  // Prefer the published "latest" release tag; fall back to the
  // highest semver tag for actions that ship tags without GitHub
  // Releases (e.g. ludeeus/action-shellcheck). Returns { tag, sha }
  // so the report can hand back a ready-to-paste pin line.
  var tag = null;
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/latest");
    // Only trust the release tag when it is semver-shaped. Some repos
    // (github/codeql-action) publish a non-semver bundle tag as their
    // "latest release" (codeql-bundle-vX.Y.Z) while the ACTION is
    // versioned on separate vN.N.N tags — fall through to tags then.
    if (rel && typeof rel.tag_name === "string" && _semverParse(rel.tag_name)) tag = rel.tag_name;
  } catch (_e) { /* fall through to tags */ }
  if (!tag) {
    var tags = await _githubGet("/repos/" + ownerRepo + "/tags?per_page=100");
    if (!Array.isArray(tags) || tags.length === 0) {
      throw new Error("no releases or tags for " + ownerRepo);
    }
    var best = null;
    for (var i = 0; i < tags.length; i++) {
      var p = _semverParse(tags[i].name);
      if (p && (!best || _semverCompare(p, best.parsed) > 0)) {
        best = { name: tags[i].name, parsed: p };
      }
    }
    if (!best) throw new Error("no semver-shaped tag for " + ownerRepo);
    tag = best.name;
  }
  return { tag: tag, sha: await _resolveSha(ownerRepo, tag) };
}

function _semverParse(v) {
  // Accept partial tags (v4 / v4.1) by treating missing segments as 0.
  var s = String(v);
  var m = s.match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  var out = [parseInt(m[1], 10), parseInt(m[2] || "0", 10), parseInt(m[3] || "0", 10)];
  // The prerelease identifiers are KEPT, not collapsed to a flag. A flag makes
  // every prerelease of one version equal, so `rc.1` reads as current against
  // `rc.2` — the gate's own failure mode, something unchecked reported as fine,
  // one layer down in the comparison. Build metadata is dropped instead of
  // kept, because semver gives it no precedence at all.
  var tail = s.slice(m[0].length);
  if (tail.charAt(0) === "-") {
    out.pre = tail.slice(1).split("+")[0].split(".");
  }
  return out;
}

// Semver precedence. Numeric triple first; then a version WITH prerelease
// identifiers ranks below the same version without them; then identifier by
// identifier — numeric compared as numbers, numeric below alphanumeric, and a
// longer run of identifiers above a shorter one when all the shared ones match.
function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  var ap = a.pre, bp = b.pre;
  if (!ap && !bp) return 0;
  if (!ap) return  1;
  if (!bp) return -1;
  for (var j = 0; j < Math.max(ap.length, bp.length); j++) {
    if (j >= ap.length) return -1;
    if (j >= bp.length) return  1;
    var x = ap[j], y = bp[j];
    var xn = /^\d+$/.test(x), yn = /^\d+$/.test(y);
    if (xn && yn) {
      var xi = parseInt(x, 10), yi = parseInt(y, 10);
      if (xi !== yi) return xi > yi ? 1 : -1;
    } else if (xn !== yn) {
      return xn ? -1 : 1;                     // numeric ranks below alphanumeric
    } else if (x !== y) {
      return x > y ? 1 : -1;                  // ASCII order
    }
  }
  return 0;
}

// A YAML block scalar header: `run: |`, `script: >-`, `- run: |2`, with an
// optional trailing comment. Returns { indent, key }, or null.
//
// This matters because the walk below is line-based and now FAILS on anything
// it cannot read as a pin. Inside a `run: |` the lines are shell, not YAML, and
// a script line that happens to start `uses: temporary credentials` is prose —
// so without this the gate refuses a perfectly good workflow. Making an
// unreadable reference loud is only correct if the set of things called
// references is right; a false positive here costs an operator a red gate on a
// file with nothing wrong in it.
//
// The KEY comes back too, because skipping is the right treatment for the block
// BODY and the wrong treatment for a `uses:` that opens one. An action
// reference is a single scalar, so `uses: |` is malformed — and quietly
// stepping over it would hand back exactly the silence the unparsed list was
// added to remove. A guard against over-refusal has to not become the next
// under-refusal.
function _blockScalarHeader(line) {
  // The header takes an indentation indicator and a chomping indicator in
  // EITHER order — `|2-` and `|-2` are both valid, and the indentation
  // indicator is a single digit 1-9. Missing a form does not merely skip a
  // block; it scans that block's shell body as YAML, so a script line reading
  // `uses: ...` fails an otherwise sound workflow.
  var m = line.match(/^([ \t]*)(?:-[ \t]+)?([A-Za-z0-9_.-]+):[ \t]*[|>](?:\d[-+]?|[-+]\d?)?[ \t]*(?:#.*)?$/);
  return m ? { indent: m[1].length, key: m[2] } : null;
}

// Whether a line sits INSIDE an open block scalar opened at `indent`. Content
// is indented further than its key; a blank line belongs to the block too, and
// anything at or left of the key's column has ended it.
function _isBlockScalarBody(line, indent) {
  if (/^[ \t]*$/.test(line)) return true;
  var lead = line.match(/^[ \t]*/)[0].length;
  return lead > indent;
}

// Split one line's `uses:` into the scalar it names and whatever follows it.
//
// This exists because the gate's whole failure mode is that an unmatched line
// is an ABSENT line, and absent reads as clean. Matching the pin pattern
// straight against the raw text made every deviation from one exact layout
// invisible: an end-of-line anchor lost the reference carrying a trailing
// comment, and a pattern expecting the owner immediately after whitespace loses
// `uses: "owner/repo@v1"`, which is an ordinary quoted YAML scalar. Reading the
// scalar FIRST and classifying it second means quoting is handled once, in the
// place that knows about quoting, rather than by a pin pattern trying to
// describe YAML.
//
// Returns null when the line carries no `uses:` key at all. `value` is null for
// a quoted scalar that is never closed — malformed, and reported rather than
// skipped.
function _usesParts(line) {
  var key = line.match(/^[ \t]*(?:-[ \t]+)?uses:[ \t]*/);
  if (!key) return null;
  var t = line.slice(key[0].length);
  if (t === "" || t.charAt(0) === "#") return null;
  var q = t.charAt(0);
  if (q === "\"" || q === "'") {
    var end = t.indexOf(q, 1);
    if (end === -1) return { value: null, after: "" };
    return { value: t.slice(1, end), after: t.slice(end + 1) };
  }
  var sp = t.search(/[ \t\r]/);
  return sp === -1
    ? { value: t.replace(/\r$/, ""), after: "" }
    : { value: t.slice(0, sp), after: t.slice(sp) };
}

// A tag naming a version, including the prerelease and build-metadata forms
// semver allows. Anchored both ends against the SCALAR — not searched for
// inside a line — so `v2.1.0-rc.1` is a tag pin rather than a near-miss that
// falls through to nothing. Rejecting a suffix here is what recreates the
// original blind spot one shape further along.
var _TAG_RE = /^v?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
var _SHA_RE = /^[0-9a-f]{40}$/;

// `uses:` values that name no upstream release, so there is no currency to
// check and skipping them is a decision rather than an oversight.
function _isUncheckableUses(value) {
  return value.charAt(0) === "." ||                     // local action in this repo
         value.indexOf("docker://") === 0;              // container image, versioned elsewhere
}

// Collect distinct SHA-pinned actions across every workflow file.
// Returns { "owner/repo": { version, refs: [{ file, line, subpath }] } }.
function _collectPinnedActions(dir) {
  var out = {};
  var root = dir || WORKFLOWS_DIR;
  var files = fs.readdirSync(root).filter(function (f) {
    return f.endsWith(".yml") || f.endsWith(".yaml");
  });
  var unparsed = [];
  // The version a SHA pin is claimed to be, from the trailing `# vX.Y[.Z]`.
  // A SHA carries no version of its own, so the comment is the only statement
  // of what it is pinned TO, and a SHA pin without one cannot be currency-
  // checked at all — which makes it unparsed, not clean.
  var verRe = /^[ \t]*#[ \t]*v?(\d+(?:\.\d+){0,2})/;
  // owner/repo, optional subpath, then the ref.
  var refRe = /^([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@(.+)$/;
  //
  // Every `uses:` key reaches one of four outcomes below, and the fourth is the
  // point of the whole rewrite. A tag pin is the reference most able to move
  // underneath us, not least: a SHA is immutable, so a stale SHA pin becomes
  // visible the moment upstream cuts a release, while a tag can be repointed at
  // new code with no local diff at all. This repository carries exactly one, and
  // by necessity — the SLSA generator refuses to run from a commit SHA — so the
  // sole exception to the pinning discipline was also the one thing the gate
  // never checked, because it matched no pattern and a reference that matches
  // nothing is absent rather than reported.
  //
  // Widening the pattern is what that lesson is NOT. It was widened twice, and
  // each time the next shape along — a trailing comment, then a quoted scalar,
  // then a prerelease suffix — landed back in the same silence. What the gate
  // can honestly promise is not "every shape is understood" but "every `uses:`
  // is either checked or named", so anything unrecognised goes into `unparsed`
  // and fails the run instead of thinning the list it reports on.
  for (var f = 0; f < files.length; f++) {
    var rel = ".github/workflows/" + files[f];
    var lines = fs.readFileSync(path.join(root, files[f]), "utf8").split("\n");
    var blockIndent = -1;
    for (var L = 0; L < lines.length; L++) {
      if (blockIndent >= 0) {
        if (_isBlockScalarBody(lines[L], blockIndent)) continue;
        blockIndent = -1;                                  // the block ended here
      }
      var hdr = _blockScalarHeader(lines[L]);
      if (hdr) {
        blockIndent = hdr.indent;                          // the body is not YAML
        if (hdr.key === "uses") {
          unparsed.push({ file: rel, line: L + 1, value: lines[L].trim(),
                          reason: "`uses:` opens a block scalar; an action " +
                                  "reference is a single scalar" });
        }
        continue;
      }
      var parts = _usesParts(lines[L]);
      if (!parts) continue;
      var at = { file: rel, line: L + 1 };
      if (parts.value === null) {
        unparsed.push({ file: rel, line: L + 1, value: lines[L].trim(),
                        reason: "unterminated quoted scalar" });
        continue;
      }
      if (_isUncheckableUses(parts.value)) continue;
      var rm = parts.value.match(refRe);
      if (!rm) {
        unparsed.push({ file: rel, line: L + 1, value: parts.value,
                        reason: "not owner/repo[/subpath]@ref" });
        continue;
      }
      var ownerRepo = rm[1];
      var subpath   = rm[2] || "";
      var ref       = rm[3];

      if (_SHA_RE.test(ref)) {
        // A SHA states no version of its own; the trailing comment is the only
        // claim about what it is pinned to, so without one there is nothing to
        // compare against upstream.
        var vm = parts.after.match(verRe);
        if (!vm) {
          unparsed.push({ file: rel, line: L + 1, value: parts.value,
                          reason: "SHA pin with no trailing '# vX.Y.Z' version comment" });
          continue;
        }
        if (!out[ownerRepo]) out[ownerRepo] = { version: vm[1], sha: null, refs: [] };
        // The entry's SHA is whichever SHA-pinned reference came first, and it
        // is only ever set from one: an action can be tag-pinned in one workflow
        // and SHA-pinned in another, and reading the entry's pin type off
        // whichever line the walk happened to reach first made both the report
        // and `--fix` depend on file iteration order.
        if (out[ownerRepo].sha === null) out[ownerRepo].sha = ref;
        out[ownerRepo].refs.push({
          file: at.file, line: at.line, subpath: subpath, tagPinned: false, sha: ref,
        });
        // If the same repo is pinned at two different versions across files,
        // record the lowest so a partial bump still flags.
        if (_semverCompare(_semverParse(vm[1]), _semverParse(out[ownerRepo].version)) < 0) {
          out[ownerRepo].version = vm[1];
        }
        continue;
      }

      if (_TAG_RE.test(ref)) {
        // A tag pin names a version, so its currency is checkable the same way;
        // what it cannot carry is a SHA to rewrite, so it is marked and `--fix`
        // leaves it alone.
        var tagVer = ref.replace(/^v/, "");
        if (!out[ownerRepo]) out[ownerRepo] = { version: tagVer, sha: null, refs: [] };
        out[ownerRepo].refs.push({
          file: at.file, line: at.line, subpath: subpath, tagPinned: true, sha: null,
        });
        if (_semverCompare(_semverParse(tagVer), _semverParse(out[ownerRepo].version)) < 0) {
          out[ownerRepo].version = tagVer;
        }
        continue;
      }

      // A branch name, a floating major, a malformed ref — pinned to something
      // that is neither immutable nor a version, so its currency cannot be
      // established. Named, not skipped.
      unparsed.push({ file: rel, line: L + 1, value: parts.value,
                      reason: "ref is neither a 40-hex SHA nor a version tag" });
    }
  }
  // Derived once every file has been read, so the answer does not depend on
  // which one was walked first. `tagPinned` means there is NOTHING here for
  // `--fix` to rewrite; an action pinned both ways still has SHA references
  // worth bumping, and is reported as mixed so the tag one is not lost in the
  // rewrite of its siblings.
  Object.keys(out).forEach(function (name) {
    var refs = out[name].refs;
    var tags = refs.filter(function (r) { return r.tagPinned; }).length;
    out[name].tagPinned = tags === refs.length;
    out[name].mixedPins = tags > 0 && tags < refs.length;
  });
  // `unparsed` rides along rather than being dropped. Returning only the map
  // is what let an unrecognised reference vanish: the caller had no way to ask
  // "and what did you NOT understand?", so a thinner list looked like a
  // cleaner tree.
  return { actions: out, unparsed: unparsed };
}

async function _checkOne(ownerRepo, entry) {
  var special = SPECIAL_MAP[ownerRepo];
  if (special && special.type === "skip") {
    return {
      action: ownerRepo, status: "skipped", reason: special.reason,
      pinned: entry.version, tagPinned: entry.tagPinned === true,
      mixedPins: entry.mixedPins === true,
    };
  }
  var pinned = _semverParse(entry.version);
  try {
    var info = await _latestVersion(ownerRepo);
    var latest = _semverParse(info.tag);
    var cmp = _semverCompare(pinned, latest);
    var status = cmp >= 0 ? "current" : "stale";
    if (special && special.type === "hold-major" && latest && latest[0] > special.major) {
      // A newer major exists but the repo intentionally holds an
      // older major — only flag stale WITHIN the held major.
      status = "current";
    }
    return {
      action:    ownerRepo,
      pinned:    entry.version,
      oldSha:    entry.sha,
      latest:    info.tag,
      latestSha: info.sha,
      status:    status,
      // Carried through so the reader and `--fix` can both tell the two kinds
      // apart: a tag pin has no SHA to rewrite, so it is reported and left for
      // a person rather than edited.
      tagPinned: entry.tagPinned === true,
      mixedPins: entry.mixedPins === true,
      refs:      entry.refs,
    };
  } catch (e) {
    return {
      action: ownerRepo,
      pinned: entry.version,
      status: "api-error",
      error:  (e && e.message) || String(e),
      // Carried on every branch, not only the one that reached the API: a
      // reader filtering for tag pins is asking which pins cannot be verified
      // by SHA, and an unreachable one is still one of them.
      tagPinned: entry.tagPinned === true,
      mixedPins: entry.mixedPins === true,
      refs:   entry.refs,
    };
  }
}

// The follow-up lines under a stale action: where it is used, and what to put
// there. Which of the two an action gets is decided per REFERENCE, not per
// action, because an action pinned by SHA in one workflow and by tag in another
// needs a different answer in each place. A SHA reference can be replaced
// verbatim, so the ready-to-paste pin line is worth printing; pasting that same
// line over a tag reference breaks it, and the SLSA generator refuses to run
// from a SHA at all. Deciding this once, off `ref.tagPinned`, is what keeps the
// printed advice and `--fix`'s behaviour from drifting apart: the report used to
// read the flag off the action and offered a SHA for every reference under it.
// The pattern `--fix` rewrites a stale SHA pin with. Group 1 is everything up
// to and including the `@`, group 2 everything between the SHA and the version,
// and both are written back verbatim — which is how a closing YAML quote
// survives. An earlier form demanded whitespace immediately after the SHA and
// so matched nothing through a quote, meaning `--fix` would have reported the
// action rewritten over a file it never touched. Widening what the collector
// ACCEPTS without widening what the fixer can REWRITE turns a blind spot into
// a false success, which is worse.
//
// It lives here, rather than inline at the one call site, so the test asserts
// against the pattern the fixer actually uses instead of a copy of it that can
// drift.
function _fixReplacementRe(action) {
  var esc = String(action).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp("(" + esc + "(?:/[^@\\s\"']+)?@)[0-9a-f]{40}([\"']?\\s*#\\s*)v?\\d+(?:\\.\\d+){0,2}", "g");
}

function _staleHints(r) {
  var refs  = r.refs || [];
  var lines = [];
  var anySha = refs.some(function (x) { return !x.tagPinned; });
  if (r.latestSha && r.latest && anySha) {
    lines.push("        pin:  " + r.action + "@" + r.latestSha + "  # " + r.latest);
  }
  for (var i = 0; i < refs.length; i++) {
    lines.push("        used: " + refs[i].file + ":" + refs[i].line +
               (refs[i].tagPinned
                 ? "  (tag pin — raise the tag by hand; a SHA does not belong here)"
                 : ""));
  }
  return lines;
}

async function main() {
  var collected = _collectPinnedActions();
  var pinned    = collected.actions;
  var unparsed  = collected.unparsed;
  var actions = Object.keys(pinned).sort();
  var results = [];
  // Sequential + polite — the action count is small and serial GETs
  // keep us well inside the API budget on shared CI IPs.
  for (var i = 0; i < actions.length; i++) {
    results.push(await _checkOne(actions[i], pinned[actions[i]]));
  }

  if (JSON_OUT) {
    _out(JSON.stringify({ results: results, unparsed: unparsed }, null, 2) + "\n");
  } else {
    var tagCount = results.filter(function (r) { return r.tagPinned; }).length;
    say("[actions-currency] " + actions.length + " pinned action(s) inspected" +
        (tagCount ? " (" + tagCount + " pinned to a tag rather than a SHA)" : "") +
        ":\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"   ? "OK"
                : r.status === "stale"     ? "STALE"
                : r.status === "api-error" ? "ERR"
                : r.status === "skipped"   ? "skip"
                :                            r.status;
      var line = "  [" + label + "] " + r.action + "  " + r.pinned;
      if (r.latest) line += " -> " + r.latest;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (api: " + r.error + ")";
      if (r.tagPinned) line += "  (tag pin — no SHA to rewrite; bump by hand)";
      else if (r.mixedPins) line += "  (pinned by SHA in some workflows and by " +
        "tag in others; --fix skips it entirely — update by hand)";
      say(line + "\n");
      if (r.status === "stale") {
        var hints = _staleHints(r);
        for (var hf = 0; hf < hints.length; hf++) say(hints[hf] + "\n");
      }
    }
    if (unparsed.length) {
      say("\n[actions-currency] " + unparsed.length + " `uses:` reference(s) could " +
          "not be read as a pin, so their currency is UNKNOWN:\n");
      for (var uz = 0; uz < unparsed.length; uz++) {
        say("  " + unparsed[uz].file + ":" + unparsed[uz].line + "  " +
            unparsed[uz].value + "\n        " + unparsed[uz].reason + "\n");
      }
      say("  Pin each to a SHA with a trailing '# vX.Y.Z', or to a version tag.\n");
    }
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "api-error"; });

  // Before any mode gets to declare success. An unreadable reference is a line
  // in this repository the gate cannot check, not a transient the network owns,
  // so unlike an api-error it fails unconditionally — and it has to be decided
  // HERE, above `--fix`, because `--fix` exits 0 on its own and would otherwise
  // report a clean repair over a tree still holding something unchecked. That
  // is the same "green while silent" shape the unparsed list exists to end.
  //
  // `--warn` keeps its documented contract of never failing, and says so.
  if (unparsed.length > 0 && !WARN_ONLY) {
    say("[actions-currency] FAIL — " + unparsed.length + " `uses:` reference(s) " +
      "could not be read as a pin (listed above). A reference the gate cannot " +
      "read is a reference it cannot check.\n");
    process.exit(1);
  }

  if (DO_FIX) {
    var byFile = {};
    var notRewritten = [];
    // Tag-only AND mixed entries are both excluded. For a tag-only one there is
    // no old SHA to rewrite, and the review material below is a diff BETWEEN
    // two SHAs, which is exactly the check a tag cannot give.
    //
    // A mixed one is excluded for a sharper reason. The entry's version is the
    // LOWEST across its references, so when the stale reference is the tag, the
    // entry reads stale while its SHA references are already current — and
    // rewriting is then actively wrong: it bumps the references that were
    // right, leaves the one that was stale, and exits 0 on a tree the next run
    // still fails. Rewriting per reference would need per-reference currency,
    // which is a larger change than this gate needs today; until then a mixed
    // entry is a person's decision and the report names every file and line.
    var fixable = stale.filter(function (r) {
      return r.latestSha && r.latest && !r.tagPinned && !r.mixedPins;
    });
    var handOnly = stale.filter(function (r) { return r.tagPinned || r.mixedPins; });
    for (var ho = 0; ho < handOnly.length; ho++) {
      var he = handOnly[ho];
      say("\n=== " + he.action + "  " + he.pinned + " -> " + he.latest + " ===\n");
      say(he.tagPinned
        ? "  pinned to a tag, so --fix leaves it alone: there is no SHA to " +
          "compare against and none to write. Update it by hand.\n"
        : "  pinned by SHA in some workflows and by tag in others, so --fix " +
          "leaves it alone: the version reported is the lowest across those " +
          "references, and rewriting the SHA ones could bump what was already " +
          "current while the stale tag stayed put. Update it by hand.\n");
      for (var hr = 0; hr < (he.refs || []).length; hr++) {
        say("        used: " + he.refs[hr].file + ":" + he.refs[hr].line +
            (he.refs[hr].tagPinned ? "  (tag)" : "  (sha)") + "\n");
      }
    }
    for (var fx = 0; fx < fixable.length; fx++) {
      var fr = fixable[fx];
      var tag = /^v/.test(fr.latest) ? fr.latest : "v" + fr.latest;
      // Supply-chain review material — printed BEFORE applying so the change
      // between the pinned SHA and the new SHA (the actual commits + authors)
      // and the release notes can be validated. A compromised release shows
      // up here as an unexpected commit / author / change.
      var cl = await _releaseChangelog(fr.action, fr.oldSha, tag, fr.latestSha);
      say("\n=== " + fr.action + "  " + fr.pinned + " -> " + fr.latest + " ===\n");
      say("  old sha: " + fr.oldSha + "\n  new sha: " + fr.latestSha + "\n");
      say("  compare: " + cl.compareUrl + "\n");
      if (cl.commits.length) {
        say("  commits between the two SHAs (" + cl.commits.length + ") [sha  author  subject]:\n");
        for (var ci = 0; ci < cl.commits.length; ci++) say("    " + cl.commits[ci] + "\n");
      } else if (cl.compareError) {
        say("  commits: (compare unavailable: " + cl.compareError + ")\n");
      }
      if (cl.files.length) {
        say("  changed files (" + cl.files.length + "):\n");
        for (var sfi = 0; sfi < cl.files.length; sfi++) {
          var sf = cl.files[sfi];
          say("    [" + sf.status + " +" + sf.add + "/-" + sf.del + "] " + sf.name + "\n");
        }
        say("  code diff (per file, capped at 200 lines):\n");
        for (var dfi = 0; dfi < cl.files.length; dfi++) {
          var df = cl.files[dfi];
          say("    ----- " + df.name + " -----\n");
          if (df.patch === null) {
            say("      (patch omitted by GitHub — file too large / binary; inspect via the compare URL above)\n");
          } else {
            var dl = df.patch.split("\n");
            for (var dk = 0; dk < Math.min(dl.length, 200); dk++) say("      " + dl[dk] + "\n");
            if (dl.length > 200) say("      ... (" + (dl.length - 200) + " more diff line(s) — see compare URL)\n");
          }
        }
      }
      if (cl.body) {
        say("  release notes for " + tag + ":\n");
        var bl = cl.body.split("\n");
        for (var bi = 0; bi < Math.min(bl.length, 40); bi++) say("    " + bl[bi] + "\n");
        if (bl.length > 40) say("    ... (" + (bl.length - 40) + " more line(s))\n");
      }
      var re2 = _fixReplacementRe(fr.action);
      // Once per FILE, not once per reference. The pattern is global, so the
      // first pass over a file already rewrites every occurrence in it; running
      // it again for a second reference to the same action in the same file
      // finds nothing left to change, and reading that as a failed rewrite
      // turns an ordinary duplicate into a false exit 1. This repository has
      // one: cosign-installer appears twice in the same workflow.
      var seenFiles = {};
      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var rel2 = fr.refs[rj].file;
        if (seenFiles[rel2]) continue;
        seenFiles[rel2] = true;
        var abs = path.join(__dirname, "..", rel2);
        if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8");
        var before = byFile[abs];
        byFile[abs] = before.replace(re2, "$1" + fr.latestSha + "$2" + tag);
        // Never report a rewrite that did not happen. Whatever shape turns up
        // next, the failure has to be loud here rather than an exit 0 over an
        // unchanged file.
        if (byFile[abs] === before) {
          notRewritten.push({ action: fr.action, file: rel2, line: fr.refs[rj].line });
        }
      }
    }
    Object.keys(byFile).forEach(function (abs) { fs.writeFileSync(abs, byFile[abs]); });
    var failedActions = {};
    notRewritten.forEach(function (n) { failedActions[n.action] = true; });
    say("\n[actions-currency] --fix: rewrote " +
      (fixable.length - Object.keys(failedActions).length) +
      " of " + fixable.length + " stale action(s) across " +
      Object.keys(byFile).length + " workflow file(s). REVIEW the changelogs above for supply-chain integrity before committing; re-run without --fix to verify.\n");
    if (notRewritten.length) {
      say("[actions-currency] --fix FAILED to rewrite " + notRewritten.length +
        " reference(s) — the pin was collected but its line did not match the " +
        "replacement, so it is still stale:\n");
      for (var nr = 0; nr < notRewritten.length; nr++) {
        say("  " + notRewritten[nr].file + ":" + notRewritten[nr].line +
            "  " + notRewritten[nr].action + "\n");
      }
      process.exit(1);
    }
    process.exit(0);
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length || unparsed.length) {
      say("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored, " + unparsed.length +
        " unreadable — exit 0 anyway\n");
    }
    process.exit(0);
  }

  var strictErrors = process.env.BLAMEJS_ACTIONS_CURRENCY_STRICT === "1";
  if (stale.length > 0 || (strictErrors && errored.length > 0)) {
    say("[actions-currency] FAIL — " + stale.length + " stale, " +
      errored.length + " api-error(s). Bump the pinned SHA + version comment to the latest release.\n");
    process.exit(1);
  }
  // Say what was CHECKED, not what was assumed. An unauthenticated run hits the
  // 60/hour per-IP limit and every lookup comes back 403 — nothing is compared,
  // and "every pinned action matches the latest upstream release" is then a
  // claim about a comparison that never ran. The exit code stays 0 because a
  // transient rate limit is not a stale action (BLAMEJS_ACTIONS_CURRENCY_STRICT
  // turns it into one), but a passing gate must not report a currency it did
  // not establish.
  if (errored.length > 0) {
    say("[actions-currency] OK for what could be checked — " +
      (results.length - errored.length) + " of " + results.length +
      " pinned action(s) match the latest upstream release; " + errored.length +
      " could not be reached, so their currency is UNKNOWN. Re-run with " +
      "GITHUB_TOKEN set for the authenticated rate limit.\n");
    process.exit(0);
  }
  say("[actions-currency] OK — every pinned action matches the latest upstream release\n");
  process.exit(0);
}

// Exported for the tests, which drive the collector over a fixture directory
// rather than over this repository's own workflows — a gate whose coverage is
// asserted against the very files it ships with can only ever confirm today's
// contents, and the defect being pinned here was a whole KIND of pin the
// collector never returned.
module.exports = {
  _collectPinnedActions: _collectPinnedActions,
  _staleHints: _staleHints,
  _fixReplacementRe: _fixReplacementRe,
  _semverParse: _semverParse,
  _semverCompare: _semverCompare,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[actions-currency] script crashed: " + (e && e.stack || e) + "\n");
    process.exit(2);
  });
}
