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

// `--fix` REWRITES pinned SHAs, and everything it prints to justify that — the
// compare URL, the commits between the two SHAs, the changed files, the diff,
// the release notes — goes through `say`. Under `--json` all of it is silent
// while the rewrite still happens, so the one combination that mutates
// supply-chain pins would be the one that shows nothing about what it pulled
// in. The JSON document is also written BEFORE the rewrite and says nothing
// about its outcome. Refusing is the honest answer: `--fix` is a review tool
// for a person, `--json` is for a machine, and neither wants the other's
// behaviour.
if (DO_FIX && JSON_OUT) {
  process.stderr.write("[actions-currency] --fix and --json cannot be combined: " +
    "--fix prints the changelog and diff a SHA rewrite has to be reviewed " +
    "against, and --json suppresses it. Run --json to inspect, then --fix to " +
    "rewrite.\n");
  process.exit(2);
}

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

async function _latestVersion(ownerRepo, pinnedIsPrerelease) {
  // Prefer the published "latest" release tag; fall back to the
  // highest semver tag for actions that ship tags without GitHub
  // Releases (e.g. ludeeus/action-shellcheck). Returns { tag, sha }
  // so the report can hand back a ready-to-paste pin line.
  var tag = null;
  // GitHub's "latest release" is by definition never a prerelease, so a pin
  // that IS one could only ever be compared against stable releases — and a
  // newer release candidate would report as current. The tag scan below sees
  // every tag, including prereleases, so a prerelease pin goes straight there.
  if (pinnedIsPrerelease) return _latestFromTags(ownerRepo, false);
  try {
    var rel = await _githubGet("/repos/" + ownerRepo + "/releases/latest");
    // Only trust the release tag when it is semver-shaped. Some repos
    // (github/codeql-action) publish a non-semver bundle tag as their
    // "latest release" (codeql-bundle-vX.Y.Z) while the ACTION is
    // versioned on separate vN.N.N tags — fall through to tags then.
    if (rel && typeof rel.tag_name === "string" && _REMOTE_TAG_RE.test(rel.tag_name)) tag = rel.tag_name;
  } catch (_e) { /* fall through to tags */ }
  // Stable-only on the fall-through. `/releases/latest` is never a prerelease by
  // definition, so a repository WITH releases already gives a stable answer; one
  // without them would otherwise have its highest tag taken whatever that is,
  // and a stable pin measured against a release candidate.
  if (!tag) return _latestFromTags(ownerRepo, true);
  return { tag: tag, sha: await _resolveSha(ownerRepo, tag) };
}

// The highest semver-shaped TAG, which unlike the releases endpoint includes
// prereleases. Used for actions that ship tags without GitHub Releases, and for
// any pin that is itself a prerelease.
var TAG_PAGE_SIZE  = 100;
// Pages, not tags — a bound on API spend, and deliberately far above what real
// repositories need. The tags endpoint is not version-ordered, so a partial scan
// cannot name the highest version and the walk refuses to guess from one; that
// makes the bound a thing that must not be hit in practice rather than a filter.
// github/codeql-action, the deepest here, holds ~900 tags across 9 pages.
var TAG_PAGE_LIMIT = 40;

// One reading of a workflow file, for everything that reads one.
//
// A leading BOM sits in front of the first key, so it is neither a space nor a
// name: the first line's indent reads wrong and its `uses` becomes invisible,
// which is this gate's original failure in miniature. Editors on Windows write
// one without asking, so it is stripped before anything looks at the text.
//
// The reason this is a function rather than two lines at the one call site: the
// collector stripped it and `--fix` did not, so the two disagreed by one
// character about where every span on the first line began. The collector
// recorded a reference, the fixer sliced one character off, the slice no longer
// contained the SHA, and the rewrite silently declined — on a file the collector
// had explicitly gone to the trouble of supporting. Two readings of one file
// that normalise differently is the whole defect, and one reader is the fix.
//
// `bom` rides back so a rewrite can put it where it found it. Stripping a byte
// out of an operator's file is not this gate's business.
function _readWorkflow(abs) {
  var text = fs.readFileSync(abs, "utf8");
  var bom  = text.charCodeAt(0) === 0xFEFF;
  if (bom) text = text.slice(1);
  return { lines: text.split("\n"), bom: bom };
}

// The highest acceptable tag among `names`, carrying `best` forward so a walk
// can fold one page at a time. Returns `{ name, parsed }` or null.
//
// Pulled out of the page walk so the selection can be tested without the
// network: which tag wins, and which are refused, is the whole substance of the
// currency answer, and behind an HTTP call it could only be exercised live.
function _highestTag(names, stableOnly, best) {
  for (var i = 0; i < (names || []).length; i++) {
    var name = names[i];
    if (typeof name !== "string") continue;
    // The SAME grammar the local collector holds a pin to. `_semverParse` reads
    // a numeric PREFIX and would happily rank `v999-invalid!` or a leading-zero
    // `v2.0.0-rc.007` as the highest version, then offer it as the replacement.
    // A remote tag has to clear the bar a local one clears.
    if (!_REMOTE_TAG_RE.test(name)) continue;
    var p = _semverParse(name);
    if (!p) continue;
    if (stableOnly && p.pre && p.pre.length) continue;
    if (!best || _semverCompare(p, best.parsed) > 0) best = { name: name, parsed: p };
  }
  return best || null;
}

// `stableOnly` refuses prerelease tags as candidates. A STABLE pin must never be
// measured against a release candidate, or told to move to one: the operator
// pinned a stable release and the gate would be spending a guarantee they chose.
// It matters here rather than only in `_latestVersion`, because that function
// falls through to this walk whenever a repository publishes no semver-shaped
// GitHub Release — and for such a repository the highest tag may well be an rc.
//
// The opposite direction is deliberately NOT filtered. A prerelease pin ranks
// against every tag, stable ones included, so a pin left on the newest rc of a
// series that has since shipped, or been overtaken, is reported stale rather
// than current forever against an abandoned line.
async function _latestFromTags(ownerRepo, stableOnly) {
  var best  = null;
  var seen  = 0;
  var complete = false;      // did the walk actually reach the end of the tags?
  for (var page = 1; page <= TAG_PAGE_LIMIT; page++) {
    var tags = await _githubGet("/repos/" + ownerRepo + "/tags?per_page=" +
                                TAG_PAGE_SIZE + "&page=" + page);
    if (!Array.isArray(tags)) break;
    seen += tags.length;
    best = _highestTag(tags.map(function (t) { return t && t.name; }),
                       stableOnly, best);
    // A short page is the end of the list; a full one means there may be more.
    if (tags.length < TAG_PAGE_SIZE) { complete = true; break; }
  }
  if (seen === 0) throw new Error("no releases or tags for " + ownerRepo);
  // A truncated scan cannot name the highest version. The tags endpoint is not
  // ordered by version, so a higher one may sit on a page never fetched, and
  // returning the best of what was seen would report a stale pin as current or
  // send `--fix` to the wrong release. Inconclusive is the honest answer, and it
  // says how far it looked.
  if (!complete) {
    throw new Error("tag scan for " + ownerRepo + " truncated at " + seen +
      " tags (" + TAG_PAGE_LIMIT + " pages) — the tags endpoint is not " +
      "version-ordered, so the highest version cannot be established from a " +
      "partial scan");
  }
  if (!best) {
    // Reached only when the walk saw the END of the tag list — a truncated scan
    // threw above — so this really is a claim about the whole of it, which is
    // what makes it a hard failure rather than an advisory one.
    var noVer = new Error("no full-version tag for " + ownerRepo +
      " — upstream publishes only floating aliases, so this pin's currency " +
      "cannot be established");
    noVer.code = "no-comparable-version";
    throw noVer;
  }
  return { tag: best.name, sha: await _resolveSha(ownerRepo, best.name) };
}

// A digit run with leading zeros trimmed, so two spellings of one number
// compare equal. Used for every numeric comparison here, core and prerelease
// alike, because both are unbounded and neither survives a double.
function _digits(s) { return String(s).replace(/^0+(?=\d)/, ""); }

// A version written with all three core components, whatever shape it arrived
// in. Upstream may publish `v4`; a pin here names `4.0.0`. Any prerelease or
// build suffix rides along unchanged.
function _fullVersion(v) {
  var p = _semverParse(v);
  if (!p) return String(v).replace(/^v/, "");
  var s = String(v).replace(/^v/, "");
  var suffix = s.slice(s.search(/[-+]/) === -1 ? s.length : s.search(/[-+]/));
  return p.coreStr.join(".") + suffix;
}

// Compares two digit runs: longer is larger, then lexicographic.
function _cmpDigits(x, y) {
  if (x.length !== y.length) return x.length > y.length ? 1 : -1;
  if (x !== y) return x > y ? 1 : -1;
  return 0;
}

function _semverParse(v) {
  // Accept partial tags (v4 / v4.1) by treating missing segments as 0.
  var s = String(v);
  var m = s.match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  var out = [parseInt(m[1], 10), parseInt(m[2] || "0", 10), parseInt(m[3] || "0", 10)];
  // The core components are ALSO kept as digit strings, and the comparison uses
  // those. A version number has no upper bound, and past Number.MAX_SAFE_INTEGER
  // two different majors round to the same double and compare equal — the same
  // precision trap the prerelease identifiers had. The numbers stay because the
  // hold-major check reads out[0] as one.
  out.coreStr = [_digits(m[1]), _digits(m[2] || "0"), _digits(m[3] || "0")];
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
  var ac = a.coreStr, bc = b.coreStr;
  for (var i = 0; i < 3; i++) {
    // Digit strings, for the same reason the prerelease identifiers are: a
    // version number is unbounded and two different ones can round to the same
    // double. The numeric fallback is for a parse that predates coreStr.
    var cc = (ac && bc) ? _cmpDigits(ac[i], bc[i])
                        : (a[i] > b[i] ? 1 : a[i] < b[i] ? -1 : 0);
    if (cc !== 0) return cc;
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
      // Compared as digit STRINGS, not numbers. A prerelease identifier has no
      // upper bound, and past Number.MAX_SAFE_INTEGER two different ones round
      // to the same double and compare equal — which reports a stale pin as
      // current, the failure this whole comparison exists to catch.
      var dc = _cmpDigits(_digits(x), _digits(y));
      if (dc !== 0) return dc;
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
// Leading whitespace width, and whether the line is blank.
function _indentOf(line) {
  var n = 0;
  while (n < line.length && (line.charAt(n) === " " || line.charAt(n) === "\t")) n++;
  return n;
}
function _isBlank(line) {
  var n = _indentOf(line);
  return n === line.length || line.charAt(n) === "\r";
}

// Whether a line sits INSIDE an open block scalar opened at `indent`. Content is
// indented further than its key; a blank line belongs to the block too, and
// anything at or left of the key's column has ended it.
function _isBlockScalarBody(line, indent) {
  if (_isBlank(line)) return true;
  return _indentOf(line) > indent;
}

// Whether a scalar is a block-scalar indicator: `|` or `>` with an optional
// indentation digit and chomping sign in EITHER order (`|2-` and `|-2` are both
// valid). Getting this wrong does not merely skip a block — it scans that
// block's shell body as YAML.
function _isBlockScalarIndicator(s) {
  if (s.length === 0 || (s.charAt(0) !== "|" && s.charAt(0) !== ">")) return false;
  var seenDigit = false, seenSign = false;
  for (var i = 1; i < s.length; i++) {
    var c = s.charAt(i);
    if (c >= "1" && c <= "9" && !seenDigit) { seenDigit = true; continue; }
    if ((c === "-" || c === "+") && !seenSign) { seenSign = true; continue; }
    return false;
  }
  return true;
}

// ---- Scanner ---------------------------------------------------------------
//
// Finding a `uses:` KEY is a question about YAML structure, and a pattern cannot
// answer it. Ten review rounds proved that the hard way, each one a shape the
// previous pattern could not see or saw wrongly: a trailing comment, a quoted
// scalar, a prerelease suffix, both block-scalar indicator orders, a `uses:`
// opening a block scalar, a flow mapping, a flow key that was not first, one
// spanning lines, a quoted key, and finally quoted script text read as a
// reference that does not exist. Widening and narrowing both failed, because
// either still asks a grammar question of a regex.
//
// So this scans. It walks characters, tracks the three states that actually
// decide whether a `uses` token is a key — am I inside a quoted scalar, inside a
// comment, inside a flow collection — and reports what it finds. Every shape
// above falls out of that at once, in both directions: a key inside a flow
// mapping IS found, and `uses:` inside a quoted string is NOT.
//
// It is the same choice the framework makes everywhere else: lib/markup-
// tokenizer.js and the guard-family primitives are hand-written scanners rather
// than patterns, for exactly this reason.

// What the scan covers, stated once and printed on every run — because the
// defect this gate was fixed for was a form it did not read and did not say so.
var SCOPE_NOTE = "every `uses:` key is scanned — block and flow style, quoted " +
                 "and plain; `uses` inside a quoted scalar, a comment or a " +
                 "block-scalar body is text, not a key";

// The escapes a double-quoted YAML scalar may contain. A workflow parser
// resolves them before it ever sees an action reference, so a scanner that
// hands back the raw text refuses `"actions/checkout@v5.0.1"` — valid YAML
// naming a perfectly ordinary action. Single-quoted scalars take no escapes at
// all beyond a doubled quote, which is why only this branch decodes.
var _YAML_ESCAPES = {
  "0": "\0",  a: "\x07", b: "\b",  t: "\t",  "\t": "\t", n: "\n",
  v: "\v",    f: "\f",   r: "\r",  e: "\x1b", " ": " ",  "\"": "\"",
  "/": "/",   "\\": "\\", N: "\x85", _: "\xa0", L: " ", P: " ",
};
var _YAML_HEX_LEN = { x: 2, u: 4, U: 8 };

function _decodeDoubleQuoted(raw) {
  if (raw.indexOf("\\") === -1) return raw;
  var out = "";
  for (var i = 0; i < raw.length; i++) {
    if (raw.charAt(i) !== "\\") { out += raw.charAt(i); continue; }
    var c = raw.charAt(i + 1);
    var hexLen = _YAML_HEX_LEN[c];
    if (hexLen) {
      var hex = raw.substr(i + 2, hexLen);
      var cp = parseInt(hex, 16);
      // A malformed escape is left verbatim rather than guessed at; it will
      // fail the reference shape and be named, which is the honest outcome.
      if (hex.length !== hexLen || !isFinite(cp)) { out += raw.charAt(i); continue; }
      out += String.fromCodePoint(cp);
      i += 1 + hexLen;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(_YAML_ESCAPES, c)) {
      out += _YAML_ESCAPES[c];
      i += 1;
      continue;
    }
    out += raw.charAt(i);
  }
  return out;
}

// Reads one scalar starting at `i`. Returns { value, end } — `value` null when a
// quoted scalar is never closed, which is malformed and reported rather than
// passed over. In a flow collection a plain scalar also ends at `,` `}` `]`.
function _readScalar(line, i, inFlow) {
  var q = line.charAt(i);
  if (q === "\"" || q === "'") {
    for (var j = i + 1; j < line.length; j++) {
      var c = line.charAt(j);
      // Only double quotes take backslash escapes; in a single-quoted scalar a
      // backslash is an ordinary character.
      if (q === "\"" && c === "\\") { j++; continue; }
      if (c === q) {
        var raw = line.slice(i + 1, j);
        return { value: q === "\"" ? _decodeDoubleQuoted(raw) : raw, end: j + 1 };
      }
    }
    return { value: null, end: line.length };
  }
  for (var k = i; k < line.length; k++) {
    var ch = line.charAt(k);
    if (ch === " " || ch === "\t" || ch === "\r") break;
    if (inFlow && (ch === "," || ch === "}" || ch === "]")) break;
    // A plain scalar cannot contain colon-space: that colon ends a key. Without
    // this the reader swallows the `:` of `uses:` and the key is never seen —
    // while `docker://alpine:3.22` and `https://…` are untouched, because their
    // colons are followed by a non-space.
    if (ch === ":") {
      var nxt = line.charAt(k + 1);
      if (k + 1 >= line.length || nxt === " " || nxt === "\t" || nxt === "\r") break;
      if (inFlow && (nxt === "," || nxt === "}" || nxt === "]")) break;
    }
  }
  return { value: line.slice(i, k), end: k };
}

// Steps over YAML node properties — an anchor (`&name`) or an explicit tag
// (`!type`) — and the whitespace after them, returning where the node itself
// begins. They may prefix a value, a mapping, a key, or an explicit key's
// value, which is exactly why this is one function: written inline it went into
// two of those four places and the other two kept reading the property AS the
// node.
function _skipNodeProperties(line, at, inFlow) {
  var j = at;
  while (j < line.length && (line.charAt(j) === "&" || line.charAt(j) === "!")) {
    var prop = _readScalar(line, j, inFlow);
    if (prop.end === j) break;
    j = prop.end;
    while (j < line.length && (line.charAt(j) === " " || line.charAt(j) === "\t")) j++;
  }
  return j;
}

// Every `uses:` key on one line, with whatever follows each value.
//
// `atKeyStart` is the whole of the structural judgement: a key can begin the
// line (after indentation and any number of sequence dashes), or follow a `{` or
// `,` inside a flow collection. It is set true at those points and false as soon
// as a scalar is read, so `uses` appearing anywhere else on the line — in a
// value, in a comment, inside quotes — is text.
// `state` carries across lines, because a flow collection can span them:
//
//     - { name: Checkout,
//         uses: owner/repo@v1.2.3 }
//
// Resetting the depth per line reads that second line as block context, so the
// comma or brace terminating the value is swallowed into the ref and a valid
// entry fails. Threading it is the whole advantage of scanning over matching —
// a pattern has nowhere to put the state at all.
//
// A new line in BLOCK context always begins where a key may appear; inside a
// flow collection it continues from wherever the previous line left off.
// Where a `uses` is an action reference, stated as the two positions the
// workflow schema actually defines:
//
//     jobs.<id>.steps[].uses      parent is `steps`
//     jobs.<id>.uses              grandparent is `jobs`
//
// Everything else spelled `uses` is data. This is an ALLOWLIST of positions
// rather than a denylist of container keys, because the containers are not
// enumerable: `strategy.matrix.include` entries carry user-defined properties,
// so `include: [{ uses: owner/repo@main }]` is a perfectly legal matrix value
// and no list of known-bad parents can predict the next one. Naming the two
// good positions is finite; naming every bad one is not.
// Whether an alias used as the VALUE of `key` at `path` conceals something the
// gate is meant to check. A job and a steps list are both containers of action
// references, so replacing either with an alias hides every reference inside it.
function _isAliasHidingActions(path, key) {
  if (path.length === 1 && path[0] === "jobs") return true;          // a whole job
  if (path.length === 2 && path[0] === "jobs" && key === "steps") return true;
  return false;
}

function _isActionRefPosition(path) {
  // The WHOLE path, anchored at the document root. Matching only the last key
  // would read `strategy.matrix.steps: [{ uses: ... }]` — user-named matrix
  // data that happens to be called `steps` — as a step, and fail the gate on a
  // workflow with nothing wrong in it. There is exactly one `steps` that means
  // steps, and it is three keys from the root.
  if (path.length === 3 && path[0] === "jobs" && path[2] === "steps") return true;
  if (path.length === 2 && path[0] === "jobs") return true;
  return false;
}

function _scanLine(line, state, eof) {
  var out = [];
  var comment = null;                    // the line's trailing comment, if any
  var commentStart = -1;                 // and where it begins, for a precise fix
  var opensBlock = null;                 // { indent, key } when the line opens one
  var i = 0;
  var flowDepth = state ? state.flowDepth : 0;
  var atKeyStart = flowDepth === 0 ? true : (state ? state.atKeyStart : true);
  // The enclosing mapping key, which is what says whether a `uses` is an action
  // reference at all. Block nesting is tracked by indentation; a flow
  // collection remembers the key that opened it. Both carry across lines.
  var stack     = state && state.stack     ? state.stack.slice()     : [];
  var flowKeys  = state && state.flowKeys  ? state.flowKeys.slice()  : [];
  // Carried, because the `{` a key introduces may begin on the NEXT line:
  //     - { with:
  //         { uses: owner/data@main } }
  // Resetting it per line drops `with` from the path, and the nested `uses`
  // then inherits the step's position and reads as an action reference.
  var pendingFlowKey = state && state.pendingFlowKey !== undefined
    ? state.pendingFlowKey : null;
  // An explicit key waiting for its `:` value line, which is always a later one.
  var explicitKey = state && state.explicitKey !== undefined
    ? state.explicitKey : null;
  // A new line in block context closes every mapping indented at or past its
  // first token, whatever kind of node follows. Doing this only when a
  // block-style KEY is met left the previous step's `uses` on the stack while a
  // flow-style step was scanned, so the flow step read as its child.
  // Not while an explicit key is pending: its `:` value line sits at the SAME
  // column as its `?`, so popping here would remove the very key the line
  // belongs to, and whatever nests under it would inherit the step's position.
  // A comment-only line carries no node, and YAML nesting does not notice it —
  // so a column-zero comment sitting between `jobs.build` and its `steps` must
  // not close them. Popping on it gave the `uses` below the wrong path, and a
  // wrong path means neither collected nor named.
  var firstCol = _indentOf(line);
  var commentOnly = !_isBlank(line) && line.charAt(firstCol) === "#";
  if (flowDepth === 0 && !_isBlank(line) && !commentOnly && !explicitKey) {
    while (stack.length && stack[stack.length - 1].indent >= firstCol) stack.pop();
  }
  // The enclosing keys, outermost first. Block nesting comes from the column
  // stack; a flow collection contributes the key that opened it, and null where
  // one was opened by a sequence dash rather than a key (`- { uses: ... }`),
  // whose enclosing key is already the last block entry.
  // An explicit `? uses` whose `:` never arrives is a malformed reference, and
  // an ordinary `uses:` with no value is already reported as one. Leaving this
  // form pending forever would put the silence back in the one shape that had
  // just been closed.
  function flushExplicit() {
    if (explicitKey && explicitKey.name === "uses" &&
        _isActionRefPosition(explicitKey.enclosing)) {
      out.push({ value: "", after: "", depth: flowDepth });
    }
    explicitKey = null;
  }

  function keyPath() {
    var p = [];
    for (var s = 0; s < stack.length; s++) p.push(stack[s].key);
    for (var fk = 0; fk < flowKeys.length; fk++) {
      if (flowKeys[fk] !== null) p.push(flowKeys[fk]);
    }
    return p;
  }

  while (i < line.length) {
    var c = line.charAt(i);

    if (c === " " || c === "\t" || c === "\r") { i++; continue; }

    // A comment runs to end of line. `#` only starts one at the beginning of a
    // token, never inside a word (`v1#2` is a scalar), which is why this is
    // reached only when a token boundary has been established. The scanner is
    // the one thing that knows where the comment really begins, so it hands the
    // text on rather than leaving the classifier to find it again — which it
    // could only do by guessing past whatever flow fields follow the value.
    if (c === "#") { comment = line.slice(i); commentStart = i; break; }

    if (c === "{" || c === "[") {
      flowDepth++;
      flowKeys.push(pendingFlowKey);
      pendingFlowKey = null;
      atKeyStart = true; i++; continue;
    }
    if (c === "}" || c === "]") {
      if (flowDepth > 0) { flowDepth--; flowKeys.pop(); }
      atKeyStart = false; i++; continue;
    }
    if (c === ",") { atKeyStart = flowDepth > 0; i++; continue; }
    // A sequence dash introduces an entry, and an entry can be a mapping whose
    // first key follows on the same line.
    if (c === "-" && (line.charAt(i + 1) === " " || line.charAt(i + 1) === "\t")) {
      atKeyStart = true; i++; continue;
    }

    // A step supplied as an ALIAS — `- *checkout`, whose anchored mapping is
    // defined elsewhere, possibly outside the two action-reference positions.
    // The step has no literal `uses` key to read, so scanning finds nothing and
    // the gate would pass having checked nothing. Resolving the alias means
    // holding the whole document, which is parsing; naming it is the answer this
    // scanner can give, and it is the loud one.
    if (atKeyStart && c === "*" && _isActionRefPosition(keyPath())) {
      var alias = _readScalar(line, i, flowDepth > 0);
      if (alias.end > i) {
        out.push({ value: null, after: "", depth: flowDepth, alias: alias.value });
        i = alias.end;
        atKeyStart = false;
        continue;
      }
    }

    // An EXPLICIT mapping key: `? uses` on one line, `: owner/repo@v1` on the
    // next. Reading `?` as an ordinary scalar clears the key position and the
    // reference is then neither checked nor named — silence, which is the one
    // outcome this collector must not have.
    if (atKeyStart && c === "?" &&
        (i + 1 >= line.length || " \t".indexOf(line.charAt(i + 1)) !== -1)) {
      flushExplicit();                    // one that never got its `:` is named
      var qk = i + 1;
      while (qk < line.length && (line.charAt(qk) === " " || line.charAt(qk) === "\t")) qk++;
      qk = _skipNodeProperties(line, qk, flowDepth > 0);
      var qName = _readScalar(line, qk, flowDepth > 0);
      // It nests like any other key, or `- ? with` / `: { uses: X }` would scan
      // that data with the step's own path and call it an action reference.
      if (flowDepth === 0) {
        while (stack.length && stack[stack.length - 1].indent >= i) stack.pop();
      }
      var qEnclosing = keyPath();
      // A key whose scalar cannot be read on this line is not a key that can be
      // dismissed. YAML permits a quoted key to carry an escaped line
      // continuation, so `? "us\` followed by `es"` resolves to `uses` — and
      // storing the null quietly would let the reference on the next line evade
      // the gate entirely, present in neither `actions` nor `unparsed`.
      //
      // This is the opposite case to a continued quoted VALUE, which stays
      // unreadable on purpose: a reference is one token with no spaces, so a
      // continuation can never hold a valid one. A KEY has no such property.
      // `uses` is four ordinary characters and a continuation can spell it, so
      // the only safe reading of an unreadable key sitting where a reference
      // could live is that it might be one.
      if (qName.value === null && _isActionRefPosition(qEnclosing)) {
        out.push({ value: null, after: "", depth: flowDepth, unreadableKey: true });
      }
      explicitKey = { name: qName.value, enclosing: qEnclosing };
      if (flowDepth === 0) stack.push({ indent: i, key: qName.value });
      i = qName.end;
      // The key position SURVIVES, because the `:` may follow on this very line
      // (`- ? uses : owner/repo@v1`) as readily as on the next. Clearing it here
      // skipped the same-line form entirely.
      atKeyStart = true;
      continue;
    }
    // The value half of one. It arrives at the start of a line as `: <value>`.
    if (atKeyStart && c === ":" && explicitKey &&
        (i + 1 >= line.length || " \t".indexOf(line.charAt(i + 1)) !== -1)) {
      var ev = i + 1;
      while (ev < line.length && (line.charAt(ev) === " " || line.charAt(ev) === "\t")) ev++;
      ev = _skipNodeProperties(line, ev, flowDepth > 0);
      // The value may itself be a collection, and it nests under this key.
      if (ev < line.length && (line.charAt(ev) === "{" || line.charAt(ev) === "[")) {
        pendingFlowKey = flowDepth === 0 ? null : explicitKey.name;
        explicitKey = null;
        i = ev; atKeyStart = false; continue;
      }
      // An alias standing in for a whole job or a whole steps list hides every
      // reference inside it, and an explicit key reaches its value through THIS
      // branch rather than the ordinary key-position one — so the check added
      // there for `steps: *the_steps` never ran for `? steps` / `: *the_steps`,
      // and the anchored definitions stayed off-path in both directions: absent
      // from `actions` and absent from `unparsed`.
      //
      // The two spellings are one shape, so they get one answer. Reading the
      // value first, since the alias check needs it either way.
      var evScalar = (ev < line.length && line.charAt(ev) !== "#")
        ? _readScalar(line, ev, flowDepth > 0) : null;
      // A block-scalar header, by the same rule as on the ordinary key path:
      // everything below belongs to the scalar rather than to YAML.
      //
      // Symmetry rather than a reachable fix, and worth saying so plainly. I
      // could not construct a workflow whose behaviour this changes, because an
      // explicit key pushes its OWN name onto the path, so anything nested
      // under it sits one level deeper than any action-reference position and
      // is already ignored — and a body at the key's own indent is not a block
      // body at all. It is kept because the asymmetry is the trap: the two
      // spellings of a mapping key reach their value through different branches
      // here, and every check that lives on only one of them is a check that is
      // simply not made for the other spelling. The alias case immediately
      // below is the same asymmetry, and that one WAS reachable.
      if (evScalar && flowDepth === 0 && _isBlockScalarIndicator(evScalar.value)) {
        var evRest = line.slice(evScalar.end).replace(/^[ \t\r]*/, "");
        if (evRest === "" || evRest.charAt(0) === "#") {
          opensBlock = { indent: _indentOf(line), key: explicitKey.name,
                         actionPosition: _isActionRefPosition(explicitKey.enclosing) };
          explicitKey = null;     // its value is the block, and it has been read
          break;
        }
      }
      if (evScalar && evScalar.value && evScalar.value.charAt(0) === "*" &&
          _isAliasHidingActions(explicitKey.enclosing, explicitKey.name)) {
        out.push({ value: null, after: "", depth: flowDepth, alias: evScalar.value });
      }
      if (explicitKey.name === "uses" && _isActionRefPosition(explicitKey.enclosing)) {
        // Spans here too. Every branch that emits an occurrence owes them, or
        // `--fix` silently declines to rewrite a reference the collector
        // reported — and the verification then fails the run over a pin that
        // was never touched.
        if (!evScalar) {
          out.push({ value: "", after: line.slice(ev), depth: flowDepth,
                     valueStart: ev, valueEnd: ev });
        } else {
          out.push({ value: evScalar.value, after: line.slice(evScalar.end),
                     depth: flowDepth, valueStart: ev, valueEnd: evScalar.end });
          ev = evScalar.end;
        }
      }
      explicitKey = null;
      i = ev;
      atKeyStart = false;
      continue;
    }

    // A node property may prefix the MAPPING as well as a value — `- &checkout
    // uses: owner/repo@v1` anchors the step, and the key follows. Consuming the
    // anchor as an ordinary scalar clears the key position, and the `uses` after
    // it then reads as text: neither checked nor named.
    if (atKeyStart && (c === "&" || c === "!")) {
      var afterProps = _skipNodeProperties(line, i, flowDepth > 0);
      if (afterProps > i) { i = afterProps; continue; }    // atKeyStart survives
    }

    var scalar = _readScalar(line, i, flowDepth > 0);
    // A scalar read can legitimately be zero-width — a bare `:` left over from
    // a mapping whose key was already consumed, for instance. Advancing past it
    // is what keeps the walk finite; without this the loop never terminates.
    if (scalar.end === i) { i++; atKeyStart = false; continue; }
    var afterScalar = scalar.end;
    // Skip spaces between the scalar and a possible `:`.
    var p = afterScalar;
    while (p < line.length && (line.charAt(p) === " " || line.charAt(p) === "\t")) p++;

    // A key is a scalar followed by `:`. Block style needs whitespace after it,
    // which is what makes `docker://x` and `https://y` plain scalars rather than
    // keys. Flow style does not: `{ a:1 }` is a mapping, and so is `{ uses:, b:
    // c }`, whose `uses` has an EMPTY value. Excluding `,}]` there treated a
    // malformed-but-present key as absent, which is the blind spot again.
    var isKey = line.charAt(p) === ":" &&
                (p + 1 >= line.length || " \t\r".indexOf(line.charAt(p + 1)) !== -1 ||
                 flowDepth > 0);

    if (atKeyStart && isKey) {
      flushExplicit();                    // an ordinary key ends any pending one
      var keyName = scalar.value;
      // Close any sibling or outer mappings this key ends BEFORE reading the
      // path, or the previous key at the same column is still on the stack and
      // reads as this one's parent — which made every step's `uses` look like a
      // child of the `name:` above it.
      if (flowDepth === 0) {
        while (stack.length && stack[stack.length - 1].indent >= i) stack.pop();
      }
      var enclosing = keyPath();                // the keys ENCLOSING this one
      if (flowDepth === 0) stack.push({ indent: i, key: keyName });
      var v = p + 1;
      while (v < line.length && (line.charAt(v) === " " || line.charAt(v) === "\t")) v++;
      v = _skipNodeProperties(line, v, flowDepth > 0);
      // A key's value may itself be a flow collection (`with: { n: 1 }`). That
      // is not a scalar, so it is handed back to the loop, which tracks the
      // nesting and reads the keys inside it. Consuming it as a scalar swallowed
      // the opening brace and lost the depth, so a `uses` key AFTER the nested
      // mapping was never seen.
      var opensNested = v < line.length &&
                        (line.charAt(v) === "{" || line.charAt(v) === "[");
      if (opensNested) {
        // A `uses:` whose value is a collection is malformed — an action
        // reference is a single scalar — so it is NAMED before descending,
        // rather than disappearing into the branch below.
        if (keyName === "uses" && _isActionRefPosition(enclosing)) {
          out.push({ value: null, after: "", depth: flowDepth });
        }
        // At block level the key is already the last entry in `stack`, so the
        // flow it opens contributes nothing further to the path.
        pendingFlowKey = flowDepth === 0 ? null : keyName;
        i = v; atKeyStart = false; continue;
      }

      var val = (v < line.length && line.charAt(v) !== "#")
        ? _readScalar(line, v, flowDepth > 0)
        : null;

      // A block-scalar header ends the structural part of the line: everything
      // below belongs to the scalar, not to YAML. Only outside a flow
      // collection, where block scalars cannot appear.
      if (val && flowDepth === 0 && _isBlockScalarIndicator(val.value)) {
        var rest = line.slice(val.end).replace(/^[ \t\r]*/, "");
        if (rest === "" || rest.charAt(0) === "#") {
          // The position travels with it. A data field named `uses` under `env`
          // or `with` may perfectly well hold a block scalar, and reporting it
          // on the key name alone would fail a sound workflow — the same
          // distinction the scanner makes everywhere else, applied here too.
          opensBlock = { indent: _indentOf(line), key: keyName,
                         actionPosition: _isActionRefPosition(enclosing) };
          break;
        }
      }

      // Only a `uses` in an action-reference POSITION. Elsewhere it is an
      // ordinary field that happens to share the name, and its value may
      // legitimately look exactly like a reference.
      // An alias VALUE anywhere an action reference could have been. The anchor
      // it names is defined elsewhere — often in data that is not an action
      // position at all — so its contents are invisible here and the job or
      // step it stands for would go unchecked entirely.
      //
      // Two shapes reach this branch rather than the key-position one above:
      //   jobs.call: *call             a whole job          enclosing = [jobs]
      //   jobs.<id>.steps: *the_steps  a whole steps list   enclosing = [jobs, <id>]
      if (val && val.value && val.value.charAt(0) === "*" &&
          _isAliasHidingActions(enclosing, keyName)) {
        out.push({ value: null, after: "", depth: flowDepth, alias: val.value });
      }
      if (keyName === "uses" && _isActionRefPosition(enclosing)) {
        // The depth AT THIS OCCURRENCE, not wherever the line ends up. A line
        // like `{ uses: owner/a@sha, with: {` finishes deeper than the `uses`
        // sits, and using the line's final depth makes a later `}` closing
        // `with` look like the pin's own mapping closing — so the pin takes that
        // line's comment (usually none) and the real version further down is
        // never seen.
        // The value's exact span rides along. `--fix` rewrites inside it and
        // nowhere else: a line can carry script text that looks like a
        // reference beside the real one, and a replacement scoped to the LINE
        // still edits both.
        out.push(val === null
          ? { value: "", after: line.slice(v), depth: flowDepth,
              valueStart: v, valueEnd: v }                        // key with no value
          : { value: val.value, after: line.slice(val.end), depth: flowDepth,
              valueStart: v, valueEnd: val.end });
      }
      // A key with no value on this line may be introducing a collection that
      // opens on the next one. Remember which key, so the `{` there records the
      // right enclosing name.
      if (val === null) pendingFlowKey = flowDepth === 0 ? null : keyName;
      // Step past this key's value either way, so its contents are never read
      // as keys.
      i = val === null ? v : val.end;
      atKeyStart = false;
      continue;
    }

    i = afterScalar;
    atKeyStart = false;
  }
  // At the end of the document an explicit key can wait no longer.
  if (eof) flushExplicit();
  return { uses: out, opensBlock: opensBlock,
           comment: comment, commentStart: commentStart,
           state: { flowDepth: flowDepth, atKeyStart: atKeyStart,
                    stack: stack, flowKeys: flowKeys,
                    pendingFlowKey: pendingFlowKey, explicitKey: explicitKey } };
}

// A tag naming a version, including the prerelease and build-metadata forms
// semver allows. Anchored both ends against the SCALAR — not searched for
// inside a line — so `v2.1.0-rc.1` is a tag pin rather than a near-miss that
// falls through to nothing. Rejecting a suffix here is what recreates the
// original blind spot one shape further along.
// The grammar of a version, written ONCE and above every use of it.
//
// Three places need it: the tag-pin test just below, the version comment a SHA
// pin carries, and the pattern `--fix` rewrites that comment with. Spelling it
// out separately in each is how they came apart — the comment matcher was
// widened to keep prerelease and build suffixes while the fixer's copy still
// stopped at the numeric triple, so a `--fix` over `# v2.1.0-rc.1` wrote
// `v2.2.0-rc.1` and exited 0 on a version that never existed. What the
// collector accepts and what the fixer can rewrite have to be the same thing by
// construction.
// Each suffix is a run of dot-separated NON-EMPTY identifiers, as semver
// defines them. Written as a loose character class it also accepted `rc.` and
// `build..oops`, which are malformed — and an empty prerelease identifier does
// not merely look odd: the comparison ranks it above a numeric one, so
// `v1.2.3-rc.` reported current against a real `v1.2.3-rc.1`. The identifier
// class excludes the dot, so the alternation cannot backtrack ambiguously.
// A PRERELEASE identifier is either `0`, a number without a leading zero, or
// something containing a non-digit — semver forbids `rc.007`, because a leading
// zero makes two spellings of one number and the comparison cannot then be
// well-defined. BUILD identifiers carry no such rule; they are not ordered at
// all, so `+007` is fine.
var _PRE_IDENT   = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
var _BUILD_IDENT = "[0-9A-Za-z-]+";
// The core components take no leading zero either — `v01.2.3` is not a semver
// version, and admitting it would give one release two spellings here just as a
// leading-zero prerelease identifier would.
var _CORE_NUM = "(?:0|[1-9]\\d*)";
// A PIN names all three components. `@v4` is a floating major — upstream
// repoints it at new code whenever it likes — so its currency cannot be
// established at all, which is the same thing a branch ref is and gets the same
// answer: named, not quietly accepted as a version.
var _VER_SRC = _CORE_NUM + "\\." + _CORE_NUM + "\\." + _CORE_NUM +
               "(?:-" + _PRE_IDENT   + "(?:\\." + _PRE_IDENT   + ")*)?" +
               "(?:\\+" + _BUILD_IDENT + "(?:\\." + _BUILD_IDENT + ")*)?";

var _TAG_RE = new RegExp("^v?" + _VER_SRC + "$");

// ONE grammar, remote and local alike.
//
// A looser remote test looked reasonable — plenty of actions publish `v4` as a
// release — and was wrong in a way that mattered: `v4` is an ALIAS that upstream
// repoints, and reading it as the concrete version 4.0.0 would report a 4.1.0
// pin as current, then write `# v4.0.0` beside a SHA that came from a moving
// reference. Zero-filling an alias invents a version nobody published.
//
// A floating release tag therefore fails this test and the lookup falls through
// to the tag scan, which is what finds the concrete `v4.2.0` underneath it.
var _REMOTE_TAG_RE = _TAG_RE;
var _SHA_RE = /^[0-9a-f]{40}$/;

// `uses:` values that name no upstream release, so there is no currency to
// check and skipping them is a decision rather than an oversight.
function _isUncheckableUses(value) {
  return value.charAt(0) === "." ||                     // local action in this repo
         value.indexOf("docker://") === 0;              // container image, versioned elsewhere
}


// The version a SHA pin is claimed to be, from its trailing `# vX.Y[.Z]`. A
// SHA states no version of its own, so the comment is the whole claim about
// what it is pinned TO. The suffixes are kept for the same reason the tag path
// keeps them: stopping at the numeric triple makes `# v2.1.0-rc.1` read as the
// final 2.1.0, so a candidate long since superseded reports current.
// The version must not be a PREFIX of something longer. Without that, a
// mistyped or non-semver `# v2.1.0rc.1` matches its `2.1.0` and the rest is
// discarded in silence, so a pin that really is a release candidate compares
// equal to the final release and reports current. Refusing to read it makes the
// gate say "no version comment", which is loud and true.
//
// The boundary rejects only what could CONTINUE a version, rather than
// demanding whitespace: `# v5.0.1, pinned for compatibility` and
// `# v5.0.1 (temporary)` are ordinary annotations and stay readable.
var _VER_COMMENT_RE = new RegExp("^[ \\t]*#[ \\t]*v?(" + _VER_SRC + ")(?![0-9A-Za-z.+-])");
// owner/repo, optional subpath, then the ref.
var _REF_RE = /^([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@(.+)$/;

// One `uses:` occurrence, sorted into exactly one outcome: collected as a SHA
// pin, collected as a tag pin, deliberately passed over, or NAMED in `unparsed`.
// There is no fifth outcome where it quietly disappears, which is the whole
// point — a reference that matches nothing used to be absent from the run, and
// absent read as clean.
function _classifyUses(parts, rel, lineNo, rawLine, comment, out, unparsed, at) {
  if (parts.value === null) {
    if (parts.unreadableKey) {
      unparsed.push({ file: rel, line: lineNo, value: rawLine.trim(),
                      reason: "explicit mapping key could not be read on this " +
                              "line — a quoted key continued onto the next one " +
                              "can resolve to `uses`, and the reference under it " +
                              "would then go unchecked; write the key as a " +
                              "single scalar" });
      return;
    }
    if (parts.alias) {
      unparsed.push({ file: rel, line: lineNo, value: rawLine.trim(),
                      reason: "step supplied as the YAML alias " + parts.alias +
                              " — the reference it resolves to cannot be read " +
                              "here; write the step out, or pin it in place" });
      return;
    }
    // Either genuinely unterminated, or a quoted scalar continued onto the next
    // line — which YAML permits and an action reference never needs, since it
    // is one token with no spaces in it. Both are named rather than guessed at,
    // and the message says what to do.
    unparsed.push({ file: rel, line: lineNo, value: rawLine.trim(),
                    reason: "quoted scalar not closed on this line — write the " +
                            "reference as a single quoted or plain scalar" });
    return;
  }
  if (_isUncheckableUses(parts.value)) return;
  var rm = parts.value.match(_REF_RE);
  if (!rm) {
    // Whatever it is, it sits in an action-reference position, so it is one —
    // an alias, a typo, an unpinned `owner/repo` with no `@ref`. A shape filter
    // here would drop it silently, which is the very thing this list exists to
    // stop; it was only ever needed back when POSITION was unknown and shape
    // was the only signal available.
    unparsed.push({ file: rel, line: lineNo, value: parts.value,
                    reason: "not a pinned action reference — expected " +
                            "owner/repo[/subpath]@<sha or version tag>" });
    return;
  }
  var ownerRepo = rm[1];
  var subpath   = rm[2] || "";
  var ref       = rm[3];

  if (_SHA_RE.test(ref)) {
    // The comment comes from the scanner, which knows where it began. Deriving
    // it from the text after the value could not see past the rest of a flow
    // mapping — `{ uses: X@sha, name: Y }  # v1.2.3` put two fields between the
    // two — and re-deciding where a comment starts is the parse question the
    // scanner exists to answer once.
    var vm = comment === null ? null : ("  " + comment).match(_VER_COMMENT_RE);
    if (!vm) {
      unparsed.push({ file: rel, line: lineNo, value: parts.value,
                      reason: "SHA pin with no trailing '# vX.Y.Z' version comment" });
      return;
    }
    if (!out[ownerRepo]) out[ownerRepo] = { version: vm[1], sha: null, refs: [] };
    // The entry's SHA is whichever SHA-pinned reference came first, and it is
    // only ever set from one: an action can be tag-pinned in one workflow and
    // SHA-pinned in another, and reading the entry's pin type off whichever line
    // the walk happened to reach first made both the report and `--fix` depend
    // on file iteration order.
    if (out[ownerRepo].sha === null) out[ownerRepo].sha = ref;
    out[ownerRepo].refs.push({
      file: rel, line: lineNo, subpath: subpath, tagPinned: false, sha: ref,
      // The version THIS reference claims, alongside the SHA it is pinned at.
      // The entry keeps only the lowest across references, and build metadata
      // carries no precedence, so `1.2.3+a` and `1.2.3+b` compare equal and the
      // aggregate silently keeps whichever was collected first. Anything asked
      // of the aggregate alone cannot see the other build identity, which is
      // the reference most likely to name different code.
      version: vm[1],
      // Exactly where the value and its version comment sit, so `--fix` edits
      // those spans and nothing else on the line.
      valueStart:   parts.valueStart,
      valueEnd:     parts.valueEnd,
      commentLine:  at ? at.commentLine  : lineNo,
      commentStart: at ? at.commentStart : -1,
    });
    // If the same repo is pinned at two different versions across files, record
    // the lowest so a partial bump still flags.
    if (_semverCompare(_semverParse(vm[1]), _semverParse(out[ownerRepo].version)) < 0) {
      out[ownerRepo].version = vm[1];
    }
    return;
  }

  if (_TAG_RE.test(ref)) {
    // A tag pin names a version, so its currency is checkable the same way;
    // what it cannot carry is a SHA to rewrite, so it is marked and `--fix`
    // leaves it alone.
    var tagVer = ref.replace(/^v/, "");
    if (!out[ownerRepo]) out[ownerRepo] = { version: tagVer, sha: null, refs: [] };
    out[ownerRepo].refs.push({
      file: rel, line: lineNo, subpath: subpath, tagPinned: true, sha: null,
      version: tagVer,
    });
    if (_semverCompare(_semverParse(tagVer), _semverParse(out[ownerRepo].version)) < 0) {
      out[ownerRepo].version = tagVer;
    }
    return;
  }

  // A branch name, a floating major, a malformed ref — pinned to something that
  // is neither immutable nor a version, so its currency cannot be established.
  // Named, not skipped.
  unparsed.push({ file: rel, line: lineNo, value: parts.value,
                  reason: "ref is neither a 40-hex SHA nor a version tag" });
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
  // Every `uses:` key reaches one of four outcomes in _classifyUses, and the
  // fourth is the
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
    var lines = _readWorkflow(path.join(root, files[f])).lines;
    var blockIndent = -1;
    var scanState = { flowDepth: 0, atKeyStart: true };
    var pending   = [];
    // One more pass than there are lines: the last carries an empty line, which
    // closes any explicit key still waiting for a `:` that never came.
    for (var L = 0; L <= lines.length; L++) {
      if (L === lines.length) {
        var tail = _scanLine("", scanState, true);
        for (var tu = 0; tu < tail.uses.length; tu++) {
          _classifyUses(tail.uses[tu], rel, lines.length, "", null, out, unparsed);
        }
        break;
      }
      if (blockIndent >= 0) {
        if (_isBlockScalarBody(lines[L], blockIndent)) continue;
        blockIndent = -1;                                  // the block ended here
      }
      var scan = _scanLine(lines[L], scanState);
      scanState = scan.state;
      for (var oc = 0; oc < scan.uses.length; oc++) {
        // Each occurrence keeps ITS OWN line's comment. A flow collection can
        // carry a comment on the `uses` line and close several lines later, and
        // it can hold more than one pin; taking the closing line's comment for
        // all of them would lose the first version and give every pin the last.
        pending.push({ parts: scan.uses[oc], line: L + 1, raw: lines[L],
                       comment: scan.comment,
                       commentLine: scan.comment !== null ? L + 1 : -1,
                       commentStart: scan.commentStart,
                       // The nesting this pin sits in. Its own mapping has
                       // closed once the depth drops below this, which is when
                       // its fallback comment is taken — a shared "most recent"
                       // one gives every pin in a collection the LAST version
                       // seen, so two mappings closing `# v1.0.0` and `# v2.0.0`
                       // would both be read as 2.0.0.
                       depth: scan.uses[oc].depth, fallback: undefined });
      }
      // A SHA pin's version lives in a trailing comment, and inside a flow
      // mapping that comment may sit after the REST of the mapping, on a later
      // line. So an occurrence waits until its mapping closes and falls back to
      // the comment there only if its own line had none. A block-style one
      // closes on its own line, so the two are the same.
      // A pin's version may sit on the line its OWN mapping closes, several
      // lines before the surrounding collection does — `steps: [ { uses: …` then
      // `},  # v1.2.3`. So the fallback is taken the moment this pin's nesting
      // unwinds, and belongs to that pin alone.
      for (var pc = 0; pc < pending.length; pc++) {
        // The boundary is this pin's OWN mapping. Its version comment is on its
        // line, or on the line that mapping closes, and nowhere else — the
        // fallback is taken at the first depth drop whether or not that line
        // carries one.
        //
        // Searching further is what looks helpful and is not: the next comment
        // outward may belong to a sibling, to the entry after it, or to the
        // collection as a whole, and nothing in the text distinguishes those.
        // `[{ uses: A@sha }, # v9.9.9 for the next one` would give A a version
        // that was never about it, and a wrong version is worse than none —
        // `--fix` acts on it. A pin whose comment sits further out is reported
        // as having none, which is loud, true, and fixed by moving the comment
        // onto the pin.
        if (pending[pc].comment === null && pending[pc].fallback === undefined &&
            scanState.flowDepth < pending[pc].depth) {
          pending[pc].fallback = scan.comment;
          if (scan.comment !== null) {
            pending[pc].commentLine  = L + 1;
            pending[pc].commentStart = scan.commentStart;
          }
        }
      }
      if (scanState.flowDepth === 0 && pending.length) {
        // A comment can be the version for AT MOST ONE reference. Where a single
        // one would serve several — `[{ uses: A@sha }, { uses: B@sha }] # v2` —
        // it identifies none of them, and handing it to all would let a pin
        // report current under a version that was never about it. Nobody claims
        // an ambiguous comment; they are reported as having none, which is what
        // is actually true.
        // Only a pin that HOLDS a comment can be in contention for one, so the
        // tally counts those alone. Keying the comment-less on their `-1:-1`
        // would have them collide with each other and take the disowning branch
        // over a comment none of them has — which reads as ambiguity and is
        // absence, and would move `fallback` off `undefined` for a reason
        // unrelated to the question being asked.
        var claims = {};
        for (var cx = 0; cx < pending.length; cx++) {
          if (pending[cx].commentStart < 0) continue;
          var ck = pending[cx].commentLine + ":" + pending[cx].commentStart;
          claims[ck] = (claims[ck] || 0) + 1;
        }
        for (var pd = 0; pd < pending.length; pd++) {
          var pe = pending[pd];
          if (pe.commentStart >= 0 &&
              claims[pe.commentLine + ":" + pe.commentStart] > 1) {
            pe.comment = null; pe.fallback = null;
            pe.commentLine = -1; pe.commentStart = -1;
          }
          var useComment = pe.comment !== null ? pe.comment
                         : pe.fallback !== undefined ? pe.fallback
                         : scan.comment;
          if (pe.comment === null && pe.fallback === undefined &&
              scan.comment !== null) {
            pe.commentLine = L + 1; pe.commentStart = scan.commentStart;
          }
          _classifyUses(pe.parts, rel, pe.line, pe.raw, useComment, out, unparsed,
                        { commentLine: pe.commentLine, commentStart: pe.commentStart });
        }
        pending.length = 0;
      }
      if (scan.opensBlock) {
        blockIndent = scan.opensBlock.indent;              // the body is not YAML
        // Skipping is right for a block BODY and wrong for a `uses:` that opens
        // one: an action reference is a single scalar, so this is malformed and
        // is named rather than stepped over.
        if (scan.opensBlock.key === "uses" && scan.opensBlock.actionPosition) {
          unparsed.push({ file: rel, line: L + 1, value: lines[L].trim(),
                          reason: "`uses:` opens a block scalar; an action " +
                                  "reference is a single scalar" });
        }
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
    // The same question asked of the release TRACK. A prerelease reference and a
    // stable one do not have the same upstream latest — `/releases/latest` skips
    // prereleases by design — so an action pinned `v1.0.0` in one workflow and
    // `v2.0.0-rc.1` in another has two different right answers and no single
    // `latest` can carry both. Whether to scan prerelease tags was being decided
    // from the aggregate, which keeps the LOWEST version: the stable pin won,
    // the prerelease track was never scanned, and the reference on it was
    // reported current against a latest that was never its own.
    //
    // Reported and left for a person, exactly as a mixed SHA/tag action is.
    // Rewriting either way is wrong rather than merely incomplete: bumping the
    // stable reference onto a release candidate trades a stability guarantee the
    // operator chose, and bumping the prerelease one needs a latest that is not
    // the action's.
    var pre = refs.filter(function (r) {
      var p = typeof r.version === "string" ? _semverParse(r.version) : null;
      return !!(p && p.pre && p.pre.length);
    }).length;
    out[name].anyPrerelease   = pre > 0;
    out[name].mixedPrerelease = pre > 0 && pre < refs.length;
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
    // Asked of every REFERENCE. `entry.version` is the LOWEST across them, so an
    // action pinned at stable `v1.0.0` and prerelease `v2.0.0-rc.1` presents the
    // stable one here, the prerelease tags are never scanned, and the reference
    // on that track is measured against a latest that excludes it by design.
    var wantPre = entry.anyPrerelease === true || !!(pinned && pinned.pre);
    // Where the references sit on BOTH tracks, one latest cannot answer for
    // them, so both are fetched and each reference is measured against its own
    // (`_staleRefs` carries the two ways a single comparison goes wrong). The
    // extra request is spent only on actions that are actually split, which in
    // practice is none of them.
    var mixedTracks = entry.mixedPrerelease === true;
    var info    = await _latestVersion(ownerRepo, mixedTracks ? false : wantPre);
    var preInfo = mixedTracks ? await _latestVersion(ownerRepo, true) : null;
    var latest = _semverParse(info.tag);
    var cmp = _semverCompare(pinned, latest);
    var behind = mixedTracks
      ? _staleRefs(entry.refs, info.tag, preInfo && preInfo.tag)
      : null;
    var status = mixedTracks ? (behind.length ? "stale" : "current")
               : cmp >= 0    ? "current"
               :               "stale";
    if (special && special.type === "hold-major" && latest && latest[0] > special.major) {
      // A newer major exists but the repo intentionally holds an
      // older major — only flag stale WITHIN the held major.
      status = "current";
    }
    // Build metadata carries no precedence — semver is explicit that
    // `1.2.3+a` and `1.2.3+b` rank equally — so ordering them would be
    // inventing a rule the spec forbids. But two builds of one version can name
    // different code, and a gate that prints "current" without mentioning it is
    // reporting more confidence than it has. So it is SAID rather than ranked.
    // Not for a split action: `cmp` is the aggregate comparison, and the
    // references it does not describe would be measured against the other
    // track's tag. A split action already carries both latests and every
    // reference's version, which is the stronger statement, so nothing is lost
    // by declining to add a weaker one on top.
    var buildNote = !mixedTracks && status === "current" && cmp === 0
      ? _buildMetadataNote(entry.refs, info.tag)
      : null;
    return {
      action:    ownerRepo,
      pinned:    entry.version,
      // No entry-level old SHA. There is no such single thing once an action is
      // pinned more than once: `pinned` is the LOWEST version across the
      // references and the entry's SHA is the FIRST one collected, so the two
      // can describe different references, and a reader pairing them gets a
      // version from one and a SHA from another. Every reference carries its
      // own `sha` in `refs`, which is the whole truth; naming one of them as
      // though it were the action's is what made a single comparison look
      // sufficient for a bump that rewrites several.
      latest:    info.tag,
      latestSha: info.sha,
      // What the PRERELEASE references are measured against, present only when
      // the references are split across both tracks. `latest` above answers for
      // the stable ones and says nothing about the others.
      //
      // Deliberately not called a prerelease latest, because it need not be one.
      // A prerelease pin ranks against every tag, stable included: an operator
      // sitting on the newest rc of a series that has since shipped, or been
      // overtaken by a later stable, is behind, and filtering stable tags out of
      // this lookup would report that pin current forever against a line nobody
      // publishes to any more. So the value here is whichever tag is highest,
      // and it is named for the role it plays rather than for its shape.
      latestForPrereleases: preInfo ? preInfo.tag : undefined,
      // Which references are behind, and on which track. For a split action the
      // single `status` is a summary of two answers, so the detail is carried
      // rather than left for the reader to work out from two latests.
      behind:    behind && behind.length ? behind : undefined,
      status:    status,
      reason:    buildNote || undefined,
      // Carried through so the reader and `--fix` can both tell the two kinds
      // apart: a tag pin has no SHA to rewrite, so it is reported and left for
      // a person rather than edited.
      tagPinned: entry.tagPinned === true,
      mixedPins: entry.mixedPins === true,
      // A stable reference and a prerelease one do not share an upstream latest,
      // so the single `latest` above is right for one track and not the other.
      // Named, and left for a person, for the same reason a mixed SHA/tag action
      // is: there is no rewrite that is correct for both.
      mixedPrerelease: entry.mixedPrerelease === true,
      refs:      entry.refs,
    };
  } catch (e) {
    return {
      action: ownerRepo,
      pinned: entry.version,
      // "The network failed" and "upstream publishes nothing comparable" are
      // different answers and must not share a status. An api-error is advisory
      // because a rate limit is not a stale action; an upstream with only
      // floating tags is a pin whose currency can never be established here, and
      // filing it as advisory would let the gate pass without ever checking it —
      // this release's whole subject, arriving from the remote side.
      status: e && e.code === "no-comparable-version" ? "no-version" : "api-error",
      error:  (e && e.message) || String(e),
      // Carried on every branch, not only the one that reached the API: a
      // reader filtering for tag pins is asking which pins cannot be verified
      // by SHA, and an unreachable one is still one of them.
      tagPinned: entry.tagPinned === true,
      mixedPins: entry.mixedPins === true,
      mixedPrerelease: entry.mixedPrerelease === true,
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
// Rewrite ONE collected reference in `lines`, in place. Returns true when the
// SHA was found where the scanner said it would be.
//
// It edits two spans and nothing else: the SHA inside the value the scanner
// read, and the version inside the comment the scanner attributed to it — which
// may be on another line when the mapping spans several. No searching, because
// searching is what kept going wrong. A pattern has to re-find the reference in
// the text, and every attempt to bound where it looked (whole file, then one
// line) still matched script text that resembled a pin and silently rewrote it.
// The scanner already knows where each reference is; the fixer is told.

// The references that are behind, each measured against the latest on ITS OWN
// release track.
//
// A stable reference and a prerelease one do not share an upstream latest:
// GitHub's `/releases/latest` never names a prerelease, while a tag scan sees
// every tag. Measuring both against one of those is wrong in both directions,
// and which way it goes is decided by whichever version happened to be lowest:
//
//   stable v2.0.0 + prerelease v3.0.0-rc.2, both current on their own tracks
//     -> aggregate lowest is 2.0.0, tag scan returns 3.0.0-rc.2, action reads
//        STALE and the gate fails over two references that are both fine.
//   stable v4.0.0 + prerelease v3.1.0-rc.1, with rc.2 published
//     -> aggregate compares 3.1.0-rc.1 against 4.0.0 and reads CURRENT, so a
//        genuinely stale release candidate goes unreported.
//
// So each reference is compared against the latest for the track it is on, and
// the action is stale when any of them is. A reference with no recorded version
// cannot be measured and is not counted here; it has already been named in
// `unparsed` by the collector.
function _staleRefs(refs, stableTag, prereleaseTag) {
  var behind = [];
  var stable = _semverParse(stableTag);
  var pre    = prereleaseTag ? _semverParse(prereleaseTag) : null;
  for (var i = 0; i < (refs || []).length; i++) {
    var r = refs[i];
    if (!r || typeof r.version !== "string") continue;
    var v  = _semverParse(r.version);
    if (!v) continue;
    var isPre  = !!(v.pre && v.pre.length);
    var target = isPre ? (pre || stable) : stable;
    if (!target) continue;
    if (_semverCompare(v, target) < 0) {
      behind.push({ file: r.file, line: r.line, version: r.version,
                    track: isPre ? "prerelease" : "stable" });
    }
  }
  return behind;
}

// The warning for references whose build metadata differs from the latest tag,
// or null when none does.
//
// Build metadata carries no precedence — semver is explicit that `1.2.3+a` and
// `1.2.3+b` rank equally — so ordering them would invent a rule the spec
// forbids. But two builds of one version can name different code, and a gate
// that prints "current" without mentioning it reports more confidence than it
// has. So it is SAID rather than ranked.
//
// Asked of every REFERENCE, never of the entry. The entry keeps the LOWEST
// version across references, and because these compare equal it keeps whichever
// was collected first — so an action pinned `1.2.3+new` in one workflow and
// `1.2.3+old` in another looks, from the entry alone, like a single reference
// that matches the latest exactly. The reference that goes unmentioned is the
// one whose build identity does not match, which is the entire reason the
// warning exists.
function _buildMetadataNote(refs, latestTag) {
  var latTag  = String(latestTag).replace(/^v/, "");
  var pinTags = [], seen = {};
  for (var i = 0; i < (refs || []).length; i++) {
    var r = refs[i];
    if (!r || typeof r.version !== "string") continue;
    var pinTag = r.version.replace(/^v/, "");
    if (Object.prototype.hasOwnProperty.call(seen, pinTag)) continue;
    seen[pinTag] = true;
    // Only when the BUILD METADATA is what differs. Equal precedence can also
    // come from forms the comparison deliberately normalises — `1` against
    // `1.0.0`, `rc.007` against `rc.7` — and those are the same release said two
    // ways, not two builds. Naming them as build differences would be exactly
    // the kind of statement that is not established.
    if (pinTag !== latTag &&
        pinTag.split("+")[0] === latTag.split("+")[0] &&
        (pinTag.indexOf("+") !== -1 || latTag.indexOf("+") !== -1)) {
      pinTags.push(pinTag);
    }
  }
  if (!pinTags.length) return null;
  return "same precedence, different build metadata (pinned " +
         pinTags.join(", ") + ", latest " + latTag + ") — semver does not " +
         "order build metadata; confirm by hand that it is the same code";
}

// The distinct SHAs a set of references is pinned at, in the order they were
// collected, and which file and line holds each.
//
// `--fix` rewrites every reference from its own SHA, so the review material it
// prints beforehand has to cover every SHA it is about to replace. Comparing
// against one of them describes one reference and silently omits the rest — and
// where that one is already current, the comparison is latest-to-latest and
// shows no commits at all while a stale sibling is rewritten unreviewed. The
// point of printing a bump for review is that a compromised release shows up in
// it, so a comparison that covers only part of the change is worse than none.
//
// Tag pins are skipped: there is no SHA to compare against. A fixable action has
// none of them, so this is a guard rather than a case.
function _distinctOldShas(refs) {
  var shas = [], where = {};
  for (var i = 0; i < (refs || []).length; i++) {
    var r = refs[i];
    if (!r || !r.sha) continue;
    if (!Object.prototype.hasOwnProperty.call(where, r.sha)) {
      where[r.sha] = [];
      shas.push(r.sha);
    }
    where[r.sha].push(r.file + ":" + r.line);
  }
  return { shas: shas, where: where };
}

function _rewriteRef(lines, ref, newSha, tag) {
  var vIdx = ref.line - 1;
  if (vIdx < 0 || vIdx >= lines.length) return false;
  // THIS reference's SHA, not the entry's. An action pinned at two different
  // SHAs across a repository has an entry carrying only the first, so rewriting
  // by that one silently skips the other and leaves it stale.
  var oldSha = ref.sha;
  if (!oldSha) return false;
  var vLine = lines[vIdx];
  var vSpan = vLine.slice(ref.valueStart, ref.valueEnd);
  if (vSpan.indexOf(oldSha) === -1) return false;
  lines[vIdx] = vLine.slice(0, ref.valueStart) +
                vSpan.replace(oldSha, newSha) +
                vLine.slice(ref.valueEnd);

  // No dedup needed: the collector gives a comment to at most one reference, and
  // refuses to attribute an ambiguous one at all — so a span reached here is
  // this reference's alone.
  var cIdx = (ref.commentLine || 0) - 1;
  if (cIdx >= 0 && cIdx < lines.length && ref.commentStart >= 0) {
    var cLine = lines[cIdx];
    lines[cIdx] = cLine.slice(0, ref.commentStart) +
      cLine.slice(ref.commentStart).replace(_VER_COMMENT_RE, function (m0, ver) {
        // Keep the comment's own `#` and spacing; swap only the version.
        return m0.slice(0, m0.lastIndexOf(ver)).replace(/v$/, "") + tag;
      });
  }
  return true;
}

function _staleHints(r) {
  var refs  = r.refs || [];
  var lines = [];
  var anySha = refs.some(function (x) { return !x.tagPinned; });
  // No paste line for an action split across release tracks. `r.latest` answers
  // for the stable references only, so a single line offered under a list that
  // includes prerelease ones is advice that is right for some of them and a
  // downgrade for the rest — the same failure as offering a SHA under a tag
  // reference, which is why that case is excluded here too.
  if (r.latestSha && r.latest && anySha && !r.mixedPrerelease) {
    // The same full-version form `--fix` writes, so a paste-ready line is one
    // the next run will actually accept.
    lines.push("        pin:  " + r.action + "@" + r.latestSha +
               "  # v" + _fullVersion(r.latest));
  }
  for (var i = 0; i < refs.length; i++) {
    // The version THIS reference claims. `pinned` on the action is the lowest
    // across all of them, so where they disagree the report named a version
    // that belongs to one line and then listed several, leaving a reader to
    // open each file to find which is actually behind. Saying it per line is
    // the difference between naming the problem and naming its neighbourhood.
    var at = typeof refs[i].version === "string" ? "  @" + refs[i].version : "";
    lines.push("        used: " + refs[i].file + ":" + refs[i].line + at +
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
    // `scope` rides the machine output for the same reason it rides the human
    // one: a consumer counting results is entitled to know what was looked at.
    _out(JSON.stringify({ scope: SCOPE_NOTE, results: results, unparsed: unparsed },
                        null, 2) + "\n");
  } else {
    var tagCount = results.filter(function (r) { return r.tagPinned; }).length;
    say("[actions-currency] " + actions.length + " pinned action(s) inspected" +
        (tagCount ? " (" + tagCount + " pinned to a tag rather than a SHA)" : "") +
        ":\n");
    say("  scope: " + SCOPE_NOTE + "\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"   ? "OK"
                : r.status === "stale"     ? "STALE"
                : r.status === "no-version" ? "NO-VER"
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
      // Said even when the action reads current, which is the case that needs
      // it most: the stable references may well be current while a prerelease
      // sibling is behind, and one status covers both.
      if (r.mixedPrerelease) line += "  (pinned to a prerelease in some " +
        "workflows and a stable release in others; the prerelease references " +
        "were checked against " + (r.latestForPrereleases || "unknown") +
        " and the stable ones against " + (r.latest || "unknown") +
        " — --fix skips it entirely)";
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
  // Structural, not transient: upstream has nothing this pin can be compared
  // against. Grouped with `unparsed` rather than with the advisory api-errors.
  var noVersion = results.filter(function (r) { return r.status === "no-version"; });

  // Before any mode gets to declare success. An unreadable reference is a line
  // in this repository the gate cannot check, not a transient the network owns,
  // so unlike an api-error it fails unconditionally — and it has to be decided
  // HERE, above `--fix`, because `--fix` exits 0 on its own and would otherwise
  // report a clean repair over a tree still holding something unchecked. That
  // is the same "green while silent" shape the unparsed list exists to end.
  //
  // `--warn` keeps its documented contract of never failing, and says so.
  if ((unparsed.length > 0 || noVersion.length > 0) && !WARN_ONLY) {
    if (unparsed.length) {
      say("[actions-currency] FAIL — " + unparsed.length + " `uses:` reference(s) " +
        "could not be read as a pin (listed above). A reference the gate cannot " +
        "read is a reference it cannot check.\n");
    }
    if (noVersion.length) {
      say("[actions-currency] FAIL — " + noVersion.length + " action(s) have no " +
        "full-version tag upstream, so their currency cannot be established:\n");
      for (var nv = 0; nv < noVersion.length; nv++) {
        say("  " + noVersion[nv].action + "  pinned " + noVersion[nv].pinned + "\n");
      }
    }
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
    //
    // A mixed RELEASE TRACK is excluded on the same reasoning. A stable
    // reference and a prerelease one have different upstream latests, so the
    // single one fetched above is right for one of them and wrong for the other,
    // and there is no rewrite that serves both: bumping the stable reference
    // onto a release candidate spends a stability guarantee the operator chose.
    var fixable = stale.filter(function (r) {
      return r.latestSha && r.latest && !r.tagPinned && !r.mixedPins &&
             !r.mixedPrerelease;
    });
    var handOnly = stale.filter(function (r) {
      return r.tagPinned || r.mixedPins || r.mixedPrerelease;
    });
    for (var ho = 0; ho < handOnly.length; ho++) {
      var he = handOnly[ho];
      say("\n=== " + he.action + "  " + he.pinned + " -> " + he.latest + " ===\n");
      say(he.tagPinned
        ? "  pinned to a tag, so --fix leaves it alone: there is no SHA to " +
          "compare against and none to write. Update it by hand.\n"
        : he.mixedPins
        ? "  pinned by SHA in some workflows and by tag in others, so --fix " +
          "leaves it alone: the version reported is the lowest across those " +
          "references, and rewriting the SHA ones could bump what was already " +
          "current while the stale tag stayed put. Update it by hand.\n"
        : "  pinned to a prerelease in some workflows and to a stable release " +
          "in others, so --fix leaves it alone: the two tracks do not share an " +
          "upstream latest, and bumping the stable references onto a release " +
          "candidate would spend a guarantee they were pinned for. Update it " +
          "by hand; the versions below say which reference is on which track.\n");
      for (var hr = 0; hr < (he.refs || []).length; hr++) {
        // This is the case where the per-reference version matters most: the
        // action is left for a person precisely BECAUSE its references disagree,
        // and the version printed above is the lowest of them. Without it here,
        // the operator is told to update by hand and not told which line is
        // behind.
        var hv = typeof he.refs[hr].version === "string"
          ? "  @" + he.refs[hr].version : "";
        say("        used: " + he.refs[hr].file + ":" + he.refs[hr].line + hv +
            (he.refs[hr].tagPinned ? "  (tag)" : "  (sha)") + "\n");
      }
    }
    for (var fx = 0; fx < fixable.length; fx++) {
      var fr = fixable[fx];
      // Written as a FULL version, whatever shape upstream published. Upstream
      // may tag a release `v4`; the collector holds a pin to `vX.Y.Z`, so
      // copying the tag verbatim would write a comment the very next run
      // refuses — a repair that breaks the thing it repaired. The two grammars
      // differ on purpose, and this is the seam between them.
      var tag = "v" + _fullVersion(fr.latest);
      // Supply-chain review material — printed BEFORE applying, so the commits,
      // the authors and the release notes behind a bump can be read first. A
      // compromised release shows up here as an unexpected commit or author.
      //
      // Grouped by distinct old SHA, one comparison each, because the loop below
      // rewrites every reference from its own; `_distinctOldShas` carries the
      // reasoning. GitHub is asked with `fr.latest`, the EXACT tag upstream
      // published, not the normalised `tag` written into the comment: a release
      // fetched by a tag that never existed 404s, the 404 is swallowed, and the
      // notes a person is meant to review the bump against go quietly missing.
      // Normalise what is written; ask with what exists.
      var grouped  = _distinctOldShas(fr.refs);
      var oldShas  = grouped.shas;
      var shaWhere = grouped.where;
      say("\n=== " + fr.action + "  " + fr.pinned + " -> " + fr.latest + " ===\n");
      var notesBody = "";
      for (var oi = 0; oi < oldShas.length; oi++) {
        var oldSha = oldShas[oi];
        if (oldShas.length > 1) {
          say("  --- pinned at " + oldSha.slice(0, 10) + " by " +
              shaWhere[oldSha].join(", ") + " ---\n");
        }
        say("  old sha: " + oldSha + "\n  new sha: " + fr.latestSha + "\n");
        if (oldSha === fr.latestSha) {
          // Nothing to review: this reference already points at the SHA being
          // written. Saying so beats printing an empty comparison, which reads
          // as "upstream changed nothing" rather than "this one was current".
          say("  already at the latest SHA — only its version comment changes\n");
          continue;
        }
        var cl = await _releaseChangelog(fr.action, oldSha, fr.latest, fr.latestSha);
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
        // The notes belong to the TAG, so they are the same whichever SHA was
        // compared against and are printed once below rather than per SHA.
        if (!notesBody && cl.body) notesBody = cl.body;
      }
      if (notesBody) {
        say("  release notes for " + tag + ":\n");
        var bl = notesBody.split("\n");
        for (var bi = 0; bi < Math.min(bl.length, 40); bi++) say("    " + bl[bi] + "\n");
        if (bl.length > 40) say("    ... (" + (bl.length - 40) + " more line(s))\n");
      }
      // Once per REFERENCE now, at the spans the scanner recorded. The old
      // pattern-based rewrite is gone: a pattern has to re-find the reference in
      // the text, and every attempt to bound where it looked — whole file, then
      // one line — still matched script text that resembled a pin. The scanner
      // already knows where each reference is, so the fixer is told rather than
      // made to search. Two occurrences of one action in a file are no longer a
      // special case either; each has its own span.
      for (var rj = 0; rj < (fr.refs || []).length; rj++) {
        var ref2 = fr.refs[rj];
        var abs  = path.join(__dirname, "..", ref2.file);
        // Through the SAME reader the collector used. The spans the scanner
        // recorded are offsets into the text it saw, so a second reading that
        // normalises differently makes every one of them point a character off.
        if (!(abs in byFile)) byFile[abs] = _readWorkflow(abs);
        _rewriteRef(byFile[abs].lines, ref2, fr.latestSha, tag);
      }
    }
    Object.keys(byFile).forEach(function (abs) {
      // The BOM goes back where it was found. `--fix` is here to change a pin,
      // not to re-encode an operator's file.
      fs.writeFileSync(abs, (byFile[abs].bom ? String.fromCharCode(0xFEFF) : "") +
                            byFile[abs].lines.join("\n"));
    });

    // Verify by RE-COLLECTING, with the same scanner that found the references
    // in the first place. "The file changed" was too weak — one occurrence
    // matching is enough to change it, so a second the replacement could not
    // reach stayed stale while the run reported success — and matching raw text
    // was too strong, since `owner/repo@<sha>` inside a comment or a matrix
    // value is not a pin at all. Asking the collector is the only check that is
    // neither: it sees exactly what the gate calls a reference.
    var after = _collectPinnedActions();
    for (var vf = 0; vf < fixable.length; vf++) {
      var want = fixable[vf];
      var got  = after.actions[want.action];
      var left = !got ? [] : (got.refs || []).filter(function (r) {
        return !r.tagPinned && r.sha !== want.latestSha;
      });
      for (var lf = 0; lf < left.length; lf++) {
        notRewritten.push({ action: want.action, file: left[lf].file,
                            line: left[lf].line });
      }
    }

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
    // A stale action `--fix` deliberately left alone — tag-only, or mixed — is
    // still stale when this exits. Exiting 0 tells a wrapper the pins were
    // updated; scripts/pin-all.js `fixActions()` reads exactly that, and would
    // report success over a tree whose next currency check still fails. The
    // rewrite that DID happen stands; the status says the job is not finished.
    if (handOnly.length) {
      say("[actions-currency] --fix: " + handOnly.length + " stale action(s) " +
        "still need a person (listed above) — the tree is not current.\n");
      process.exit(1);
    }
    process.exit(0);
  }

  if (WARN_ONLY) {
    if (stale.length || errored.length || unparsed.length || noVersion.length) {
      say("[actions-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored, " + unparsed.length + " unreadable, " +
        noVersion.length + " with no upstream version — exit 0 anyway\n");
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
  _rewriteRef: _rewriteRef,
  _distinctOldShas: _distinctOldShas,
  _buildMetadataNote: _buildMetadataNote,
  _staleRefs: _staleRefs,
  _highestTag: _highestTag,
  _readWorkflow: _readWorkflow,
  _fullVersion: _fullVersion,
  SCOPE_NOTE: SCOPE_NOTE,
  _semverParse: _semverParse,
  _semverCompare: _semverCompare,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[actions-currency] script crashed: " + (e && e.stack || e) + "\n");
    process.exit(2);
  });
}
