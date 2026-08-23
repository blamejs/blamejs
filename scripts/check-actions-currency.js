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
      // Compared as digit STRINGS, not numbers. A prerelease identifier has no
      // upper bound, and past Number.MAX_SAFE_INTEGER two different ones round
      // to the same double and compare equal — which reports a stale pin as
      // current, the failure this whole comparison exists to catch.
      var xs = x.replace(/^0+(?=\d)/, ""), ys = y.replace(/^0+(?=\d)/, "");
      if (xs.length !== ys.length) return xs.length > ys.length ? 1 : -1;
      if (xs !== ys) return xs > ys ? 1 : -1;
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
  if (flowDepth === 0 && !_isBlank(line) && !explicitKey) {
    var lineIndent = _indentOf(line);
    while (stack.length && stack[stack.length - 1].indent >= lineIndent) stack.pop();
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
      out.push({ value: "", after: "" });
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
    if (c === "#") { comment = line.slice(i); break; }

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
      explicitKey = { name: qName.value, enclosing: keyPath() };
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
      if (explicitKey.name === "uses" && _isActionRefPosition(explicitKey.enclosing)) {
        if (ev >= line.length || line.charAt(ev) === "#") {
          out.push({ value: "", after: line.slice(ev) });
        } else {
          var evVal = _readScalar(line, ev, flowDepth > 0);
          out.push({ value: evVal.value, after: line.slice(evVal.end) });
          ev = evVal.end;
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
          out.push({ value: null, after: "" });
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
      if (keyName === "uses" && _isActionRefPosition(enclosing)) {
        out.push(val === null
          ? { value: "", after: line.slice(v) }                    // key with no value
          : { value: val.value, after: line.slice(val.end) });
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
  return { uses: out, opensBlock: opensBlock, comment: comment,
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
var _VER_SRC = "\\d+(?:\\.\\d+){0,2}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\\+[0-9A-Za-z][0-9A-Za-z.-]*)?";

var _TAG_RE = new RegExp("^v?" + _VER_SRC + "$");
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
var _VER_COMMENT_RE = new RegExp("^[ \\t]*#[ \\t]*v?(" + _VER_SRC + ")");
// owner/repo, optional subpath, then the ref.
var _REF_RE = /^([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)(\/[^@\s]+)?@(.+)$/;

// One `uses:` occurrence, sorted into exactly one outcome: collected as a SHA
// pin, collected as a tag pin, deliberately passed over, or NAMED in `unparsed`.
// There is no fifth outcome where it quietly disappears, which is the whole
// point — a reference that matches nothing used to be absent from the run, and
// absent read as clean.
function _classifyUses(parts, rel, lineNo, rawLine, comment, out, unparsed) {
  if (parts.value === null) {
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
    var lines = fs.readFileSync(path.join(root, files[f]), "utf8").split("\n");
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
                       comment: scan.comment });
      }
      // A SHA pin's version lives in a trailing comment, and inside a flow
      // mapping that comment may sit after the REST of the mapping, on a later
      // line. So an occurrence waits until its mapping closes and falls back to
      // the comment there only if its own line had none. A block-style one
      // closes on its own line, so the two are the same.
      if (scanState.flowDepth === 0 && pending.length) {
        for (var pd = 0; pd < pending.length; pd++) {
          _classifyUses(pending[pd].parts, rel, pending[pd].line, pending[pd].raw,
                        pending[pd].comment !== null ? pending[pd].comment : scan.comment,
                        out, unparsed);
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
  return new RegExp("(" + esc + "(?:/[^@\\s\"']+)?@)[0-9a-f]{40}([\"']?\\s*#\\s*)v?" +
                    _VER_SRC, "g");
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
