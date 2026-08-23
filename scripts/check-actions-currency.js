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
  var m = String(v).match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2] || "0", 10), parseInt(m[3] || "0", 10)];
}

function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

// Collect distinct SHA-pinned actions across every workflow file.
// Returns { "owner/repo": { version, refs: [{ file, line, subpath }] } }.
function _collectPinnedActions(dir) {
  var out = {};
  var root = dir || WORKFLOWS_DIR;
  var files = fs.readdirSync(root).filter(function (f) {
    return f.endsWith(".yml") || f.endsWith(".yaml");
  });
  // `uses: owner/repo[/subpath]@<40-hex-sha>  # vX.Y[.Z]`
  var re = /uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@([0-9a-f]{40})\s*#\s*v?(\d+(?:\.\d+){0,2})/;
  // The same line pinned to anything that is NOT a 40-hex SHA — a tag, most
  // often. The pattern above cannot match one, so such a pin was collected by
  // nothing and reported as neither current nor stale: absent from the run
  // entirely, while the summary counted only what it had looked at and read as
  // a clean bill.
  //
  // That is the pin most able to move underneath us, not least. A SHA is
  // immutable, so a stale SHA pin is visible the moment upstream releases; a
  // tag can be repointed at new code with no diff here at all. This repository
  // carries exactly one, and by necessity: the SLSA generator refuses to run
  // from a commit SHA, so `generator_generic_slsa3.yml` is pinned to a tag and
  // is the sole exception to the pinact discipline — which made it the one
  // thing the currency gate never checked.
  // The version is closed with a lookahead rather than an end-of-line anchor:
  // the one line this exists to catch carries a trailing `# zizmor: ignore[…]`
  // comment explaining why it is not SHA-pinned, so anchoring at `$` matched
  // nothing and the pin stayed invisible — the same blind spot one level down.
  // The lookahead also keeps a SHA from being read as a version: `@11bd7190…`
  // starts with digits, and only the requirement that the number END there
  // rejects it.
  var tagRe = /uses:\s*([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@(v?\d+(?:\.\d+){0,2})(?=\s|$)/;
  for (var f = 0; f < files.length; f++) {
    var rel = ".github/workflows/" + files[f];
    var lines = fs.readFileSync(path.join(root, files[f]), "utf8").split("\n");
    for (var L = 0; L < lines.length; L++) {
      var m = lines[L].match(re);
      if (!m) {
        // Not SHA-pinned. A tag pin still names a version, so its currency is
        // checkable the same way; what it cannot carry is a SHA to rewrite, so
        // it is marked and `--fix` leaves it alone.
        var t = lines[L].match(tagRe);
        if (!t) continue;
        var tagRepo = t[1];
        var tagVer  = t[3].replace(/^v/, "");
        if (!out[tagRepo]) out[tagRepo] = { version: tagVer, sha: null, refs: [] };
        out[tagRepo].refs.push({
          file: rel, line: L + 1, subpath: t[2] || "", tagPinned: true, sha: null,
        });
        if (_semverCompare(_semverParse(tagVer), _semverParse(out[tagRepo].version)) < 0) {
          out[tagRepo].version = tagVer;
        }
        continue;
      }
      var ownerRepo = m[1];
      var subpath   = m[2] || "";
      var sha       = m[3];
      var version   = m[4];
      if (!out[ownerRepo]) out[ownerRepo] = { version: version, sha: null, refs: [] };
      // The entry's SHA is whichever SHA-pinned reference came first, and it is
      // only ever set from one: an action can be tag-pinned in one workflow and
      // SHA-pinned in another, and reading the entry's pin type off whichever
      // line the walk happened to reach first made both the report and `--fix`
      // depend on file iteration order.
      if (out[ownerRepo].sha === null) out[ownerRepo].sha = sha;
      out[ownerRepo].refs.push({
        file: rel, line: L + 1, subpath: subpath, tagPinned: false, sha: sha,
      });
      // If the same repo is pinned at two different versions across
      // files, record the lowest so a partial bump still flags.
      if (_semverCompare(_semverParse(version), _semverParse(out[ownerRepo].version)) < 0) {
        out[ownerRepo].version = version;
      }
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
  return out;
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
  var pinned = _collectPinnedActions();
  var actions = Object.keys(pinned).sort();
  var results = [];
  // Sequential + polite — the action count is small and serial GETs
  // keep us well inside the API budget on shared CI IPs.
  for (var i = 0; i < actions.length; i++) {
    results.push(await _checkOne(actions[i], pinned[actions[i]]));
  }

  if (JSON_OUT) {
    _out(JSON.stringify({ results: results }, null, 2) + "\n");
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
        "tag in others; --fix rewrites only the SHA ones)";
      say(line + "\n");
      if (r.status === "stale") {
        var hints = _staleHints(r);
        for (var hf = 0; hf < hints.length; hf++) say(hints[hf] + "\n");
      }
    }
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "api-error"; });

  if (DO_FIX) {
    var byFile = {};
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
      var esc = fr.action.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      var re2 = new RegExp("(" + esc + "(?:/[^@\\s]+)?@)[0-9a-f]{40}(\\s*#\\s*)v?\\d+(?:\\.\\d+){0,2}", "g");
      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var abs = path.join(__dirname, "..", fr.refs[rj].file);
        if (!(abs in byFile)) byFile[abs] = fs.readFileSync(abs, "utf8");
        byFile[abs] = byFile[abs].replace(re2, "$1" + fr.latestSha + "$2" + tag);
      }
    }
    Object.keys(byFile).forEach(function (abs) { fs.writeFileSync(abs, byFile[abs]); });
    say("\n[actions-currency] --fix: rewrote " + fixable.length + " stale action(s) across " +
      Object.keys(byFile).length + " workflow file(s). REVIEW the changelogs above for supply-chain integrity before committing; re-run without --fix to verify.\n");
    process.exit(0);
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length) {
      say("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored — exit 0 anyway\n");
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
  _semverParse: _semverParse,
  _semverCompare: _semverCompare,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[actions-currency] script crashed: " + (e && e.stack || e) + "\n");
    process.exit(2);
  });
}
