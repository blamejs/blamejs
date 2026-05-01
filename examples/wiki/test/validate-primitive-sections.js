"use strict";
/**
 * validate-primitive-sections — wiki convention enforcer.
 *
 * Walks every page seeder under examples/wiki/seeders/prod/pages/ and
 * verifies every primitive section ships the four pieces required by
 * the project's wiki-section convention:
 *
 *   1. Heading — <h2> or <h3> whose text begins with `b.module.method(...)`
 *   2. Opts model — first javascript code block when signature names opts
 *   3. Description prose — at least one <p> or <aside> in the section
 *   4. Example code — at least one non-opts code block (js or bash)
 *
 * Beyond presence, the validator does two deeper passes:
 *
 *   Pre-boot pass — opts diff (this file, runs pre-boot from e2e step 0)
 *     For sections whose heading is a single-method `b.X.Y(opts)` form,
 *     probe the lib function with an unknown key, parse the
 *     "Allowed keys:" / "Allowed:" list from the validation error,
 *     and diff against the keys parsed from the wiki opts block.
 *     Drift surfaces as "added" (wiki has a key the lib doesn't accept)
 *     or "removed" (lib has a key the wiki doesn't document).
 *
 *   Post-boot pass — example execution (runExamples export, runs post-boot
 *     from e2e after the wiki app starts)
 *     Each non-opts javascript example block runs in a sandboxed async
 *     wrapper with the framework + helper stubs in scope. Syntax errors
 *     and runtime ReferenceErrors against undefined real-framework
 *     symbols fail the gate. Examples referencing operator-stubbed
 *     names (req/res/db rows) get harness stubs so they don't trip on
 *     scope alone — the harness fails only when the example calls a
 *     b.X.Y that doesn't exist or passes args the lib rejects.
 *
 * Sections whose heading text doesn't match the primitive signature
 * pattern (purely conceptual subsections like "Tenant-per-row vs
 * tenant-per-schema") are NOT validated — they're concept groups, not
 * primitive docs.
 *
 * Genuinely-deviant primitive sections (CLI subcommands documented as
 * a single bash example, narrative-shaped primitives that fold their
 * opts into the description) live in EXEMPTIONS below with a one-line
 * reason. New primitives must conform; the gate fails on any new
 * violation.
 *
 * Run standalone:
 *   node examples/wiki/test/validate-primitive-sections.js
 *   node examples/wiki/test/validate-primitive-sections.js --report
 *     (report-only mode, exits 0 even with violations — useful when
 *      iterating on the exemptions list)
 *
 * Run as part of wiki e2e:
 *   node examples/wiki/test/e2e.js
 *   (validator runs first; e2e refuses to start if the validator fails)
 */
var fs = require("fs");
var path = require("path");

// ---- Exemptions ----
//
// Sections explicitly EXCLUDED from the validator's bar. The naming
// is inverted from "allowlist" because that's what the list does:
// items here are exempted from passing the four-piece check, with a
// stated reason. Format: { "page-slug:lowercased-heading-prefix": "reason" }.
// The match key is the slug + ":" + lowercase first-50-chars of the
// heading signature. Each reason should read in 5 seconds —
// "deferred", "compound primitive", "CLI bash-only".
//
// Every entry is future drift unless paired with a tracking note in
// the v0.6.x backlog. Prefer closing the gap in the same patch over
// adding here.
var EXEMPTIONS = {
  // Sections whose examples genuinely can't run inside a sandboxed
  // harness because the surface depends on browser-side state, an
  // external network endpoint, or a third-party identity provider
  // the validator can't simulate. Each entry lists the reason an
  // operator could read in 5 seconds.
  "auth:b.auth.passkey.startregistration(opts) / .verifyre":
    "WebAuthn ceremony — verifyRegistration consumes a browser-side AttestationResponse",
  "auth:b.auth.passkey.startauthentication(opts) / .verify":
    "WebAuthn ceremony — verifyAuthentication consumes a browser-side AssertionResponse",
  "auth:b.auth.oauth.create(opts)":
    "OAuth flow needs a real provider (Google/GitHub/etc.) for the token-exchange round trip",
  "observability:b.otelexport.create(opts)":
    "OTLP/HTTP export connects to an operator-side OTel collector — the example has a real Honeycomb URL",
  // breakGlass passkey + service-account variants need a real WebAuthn
  // attestation chain or a pre-issued service-account key that the
  // sandboxed validator harness can't synthesize.
  "access-control:b.breakglass.policy.set(table, opts)":
    "compound section covering passkey + service-account paths that need external state",
  "access-control:b.breakglass.grant(opts)":
    "covered by the b.breakGlass.policy.set cluster's exemption",
  // Cluster + scheduler examples need a real externalDb provider for
  // leader election (Postgres advisory locks). The validator's fake-
  // backend can't satisfy that contract; the actual cluster e2e covers
  // these paths from the ground up.
  "cluster:b.cluster.init(opts)":
    "needs a real externalDb leader-election provider (Postgres advisory lock)",
  "cluster:b.scheduler.create(opts)":
    "needs a cluster instance for the leader-gated tick path",
  "cluster:b.externaldb.init(opts)":
    "init example uses operator-defined connect/query — covered by externalDb-routing tests",
  "auth:b.auth.jwt.sign(claims, opts) / .verify(token, opt":
    "JWT signing in example uses operator-supplied keys; PEM parser fixture mismatch is environmental",
  "auth:b.auth.lockout.create(opts)":
    "cache backend 'cluster' needs cluster.init upstream — exempt for the same reason as cluster:* sections",
  "i18n-locale:b.i18n.create(opts)":
    "example imports a translations module via require() — that module path is operator-supplied",
  "mail:b.mail.create(opts)":
    "SMTP transport example would dial smtp.example.com — operator-network-only path",
  "mail:b.mail.dkim.create(opts)":
    "DKIM signs with operator-supplied PEM; the example demonstrates the call shape",
  "notifications:b.notify.create(opts)":
    "example wires Slack/Discord http webhook URLs — outbound https-only by default and the harness uses test stubs",
  "object-store:b.storage.presigneduploadpolicy(key, opts)":
    "S3 presigned-policy example needs an operator-supplied S3 backend — local-file backend doesn't support presign",
  "queue-cache:b.cache.create(opts)":
    "example references apiCache (operator-defined cache instance) by name in a multi-line composition",
  "reliability:b.retry.withretry(fn, opts)":
    "compound section that demonstrates retry + circuit-breaker composition — `guarded` references the breaker example's local",
  "websockets:b.websocketchannels.create(opts)":
    "example wires router.ws() with operator-supplied per-channel auth handlers",
  "observability:b.audit.safeemit(event)":
    "example shows compound emission in a route handler — references operator-side `body` from req parsing",
};

// Primitive signature pattern: heading begins with `b.module.method`
// (chained dotted form). May be wrapped in `<code>...</code>` markup.
//
// Examples that match:
//   "b.db.declareView(opts)"
//   "b.cache.set(key, value, opts?) / cache.wrap(key, fn)"
//
// Examples that DON'T match (conceptual sections, framework-internal):
//   "Three threat models"
//   "Tenant-per-row vs tenant-per-schema"
//   "Per-cell encryption with context binding"
//   "Pick your defenses"
var PRIMITIVE_SIGNATURE_RE = /^\s*(?:<code>\s*)?b\.[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)+/;

// ---- Parser ----

function _readPageBodies() {
  var pagesDir = path.join(__dirname, "..", "seeders", "prod", "pages");
  var files = fs.readdirSync(pagesDir)
    .filter(function (f) { return f.endsWith(".js") && f !== "_index.js"; });
  return files.map(function (f) {
    var mod = require(path.join(pagesDir, f));
    return {
      file: f,
      slug: mod.slug,
      title: mod.title,
      body: Array.isArray(mod.body) ? mod.body.join("\n") : String(mod.body || ""),
    };
  });
}

function _headingText(rawHeading) {
  var stripped = rawHeading
    .replace(/<a\s+class="anchor"[^>]*>[^<]*<\/a>/gi, "")
    .replace(/<\/?h[1-6][^>]*>/gi, "")
    .trim();
  return stripped;
}

// Split a page body into sections at every <h2> and <h3>. Each section
// carries its heading tag, heading-text-only, and the body content
// from after the heading until the next heading (or end of page).
function _splitSections(body) {
  var matches = [];
  var headingRe = /<h([23])\b[^>]*>([\s\S]*?)<\/h\1>/g;
  var iter = body.matchAll(headingRe);
  for (var m of iter) {
    matches.push({
      level:    Number(m[1]),
      raw:      m[0],
      text:     _headingText(m[0]),
      startIdx: m.index,
      endIdx:   m.index + m[0].length,
    });
  }
  for (var i = 0; i < matches.length; i++) {
    var nextStart = (i + 1 < matches.length) ? matches[i + 1].startIdx : body.length;
    matches[i].content = body.slice(matches[i].endIdx, nextStart);
  }
  return matches;
}

function _isPrimitiveHeading(text) {
  return PRIMITIVE_SIGNATURE_RE.test(text);
}

// Heuristic: signature names `opts` (or `opts?`) somewhere in its arg
// list. Multi-method signatures count as opts-naming if ANY method
// takes an opts.
function _signatureNamesOpts(text) {
  return /\bopts\??\s*[,)]/.test(text) ||
         /\bopts\??\s*$/.test(text);
}

// Strip leading whitespace and `//` line-comments so we can look at
// the first significant character. Pages frequently prefix the opts
// block with a `// hash opts (and needsRehash opts):` line — the
// `{` follows.
function _firstSignificantChar(code) {
  var lines = code.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var trimmed = lines[i].replace(/^\s+/, "");
    if (trimmed.length === 0) continue;        // blank line
    if (trimmed.indexOf("//") === 0) continue; // line-comment
    return trimmed.charAt(0);
  }
  return "";
}

// Find every <pre><code class="language-..."> block and classify it.
// Returns [{ language, content, looksLikeOpts }].
function _extractCodeBlocks(content) {
  var re = /<pre[^>]*>\s*<code[^>]*class="language-(\w+)"[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/g;
  var iter = content.matchAll(re);
  var out = [];
  for (var m of iter) {
    var lang = m[1];
    var code = m[2];
    var firstSig = _firstSignificantChar(code);
    out.push({
      language:      lang,
      content:       code,
      looksLikeOpts: lang === "javascript" && firstSig === "{",
    });
  }
  return out;
}

function _hasDescriptionProse(content) {
  return /<p\b/.test(content) || /<aside\b/.test(content);
}

// ---- Wiki opts-block parser ----
//
// Pulls the top-level keys from a literal-form opts block:
//
//   {
//     keyA:  string,                     // required: true
//     keyB:  number,                     // default: 30
//     keyC:  { nested: ... },            // — nested entries skipped
//   }
//
// Strategy: locate the outermost balanced `{ ... }` after stripping
// leading whitespace + comments. Walk the body, tracking brace/bracket/
// paren depth. At depth 0, a top-level entry runs from the previous
// `,` (or start) until the next top-level `,`. Each entry's first
// identifier before the first `:` is the key.

function _decodeHtmlEntities(s) {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
          .replace(/&#39;/g, "'");
}

function _stripJsLineComments(s) {
  // Strip `// ...` to end of line, line by line. Avoid stripping `//`
  // that appears inside a string literal — if seen, abandon line and
  // keep as-is. Simple-but-conservative: skip stripping when the line
  // contains an odd number of `'` or `"` before the `//`.
  return s.split("\n").map(function (line) {
    var idx = line.indexOf("//");
    if (idx < 0) return line;
    var before = line.slice(0, idx);
    var sq = (before.match(/'/g) || []).length;
    var dq = (before.match(/"/g) || []).length;
    if (sq % 2 !== 0 || dq % 2 !== 0) return line;
    return before;
  }).join("\n");
}

function _findOpenBrace(code) {
  // Skip leading whitespace + line comments. Return index of the
  // first `{` we encounter that's the start of the opts object.
  for (var i = 0; i < code.length; i++) {
    var c = code.charAt(i);
    if (c === " " || c === "\t" || c === "\n" || c === "\r") continue;
    if (c === "/" && code.charAt(i + 1) === "/") {
      var nl = code.indexOf("\n", i);
      if (nl < 0) return -1;
      i = nl;
      continue;
    }
    if (c === "{") return i;
    return -1;  // anything else means this isn't an opts block
  }
  return -1;
}

function _matchClosingBrace(code, openIdx) {
  var depth = 0;
  for (var i = openIdx; i < code.length; i++) {
    var c = code.charAt(i);
    if (c === '"' || c === "'") {
      // Skip string literal.
      var q = c;
      i++;
      while (i < code.length && code.charAt(i) !== q) {
        if (code.charAt(i) === "\\") i++;
        i++;
      }
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function _extractWikiOptsKeys(code) {
  var decoded = _decodeHtmlEntities(code);
  var stripped = _stripJsLineComments(decoded);
  var openIdx = _findOpenBrace(stripped);
  if (openIdx < 0) return null;
  var closeIdx = _matchClosingBrace(stripped, openIdx);
  if (closeIdx < 0) return null;
  var inner = stripped.slice(openIdx + 1, closeIdx);

  var keys = [];
  var depth = 0;
  var entryStart = 0;
  for (var i = 0; i < inner.length; i++) {
    var c = inner.charAt(i);
    if (c === '"' || c === "'") {
      var q = c;
      i++;
      while (i < inner.length && inner.charAt(i) !== q) {
        if (inner.charAt(i) === "\\") i++;
        i++;
      }
      continue;
    }
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") depth--;
    else if (c === "," && depth === 0) {
      _pushEntryKey(inner.slice(entryStart, i), keys);
      entryStart = i + 1;
    }
  }
  _pushEntryKey(inner.slice(entryStart), keys);
  return keys;
}

function _pushEntryKey(entry, out) {
  var trimmed = entry.replace(/^\s+|\s+$/g, "");
  if (trimmed.length === 0) return;
  var colonIdx = trimmed.indexOf(":");
  if (colonIdx < 0) return;
  var key = trimmed.slice(0, colonIdx).replace(/^\s+|\s+$/g, "");
  // Strip surrounding quotes if present
  key = key.replace(/^["']|["']$/g, "");
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) return;
  if (out.indexOf(key) === -1) out.push(key);
}

// ---- Lib allow-list probe ----
//
// Strategy: resolve `b.module.method(opts)` to the actual function,
// then call it with `{ <unique-key>: 1 }`. Most factories run a
// validateOpts (or in-line allow-list check) immediately and throw an
// error whose message contains the canonical allow-list. Two formats
// the framework emits:
//
//   "primitive: unknown option 'X'. Allowed keys: a, b, c."
//      (lib/validate-opts.js — the dominant pattern)
//
//   "unknown opt 'X'. Allowed: a, b, c"
//      (lib/db-declare-view.js / lib/db-declare-row-policy.js custom
//       form — same idea, slightly different wording)
//
// When the probe doesn't throw, or throws a different shape, the
// section's opts diff is skipped with a recorded reason. Presence
// remains enforced for those.

function _resolveSignaturePath(b, signature) {
  var match = signature.match(/^\s*(?:<code>\s*)?b\.([a-zA-Z0-9_.]+)\s*\(/);
  if (!match) return null;
  var path = match[1].split(".");
  var current = b;
  for (var i = 0; i < path.length; i++) {
    if (current === null || current === undefined) return null;
    current = current[path[i]];
  }
  return typeof current === "function" ? current : null;
}

function _probeAllowList(fn) {
  if (typeof fn !== "function") {
    return { ok: false, reason: "not-a-function" };
  }
  var probeKey = "__validator_probe_" + Date.now() + "_" + Math.random().toString(36).slice(2);
  var probeOpts = {};
  probeOpts[probeKey] = true;
  var thrown = null;
  try {
    var result = fn(probeOpts);
    // Async factories return a promise. The validation throw in the
    // sync prologue is what we want; if we got here without throwing,
    // there's no validateOpts on the sync path.
    if (result && typeof result.then === "function") {
      // Swallow the rejection silently — we only care that NOTHING
      // threw synchronously. (Promise rejections fire asynchronously
      // and can't be observed without a synchronous .catch handler;
      // queueing one keeps Node from logging an unhandled rejection.)
      result.then(function () {}, function () {});
      return { ok: false, reason: "async-no-sync-validateOpts" };
    }
    return { ok: false, reason: "no-throw-on-unknown-key" };
  } catch (e) {
    thrown = e;
  }
  var msg = (thrown && thrown.message) || "";
  // Two error message formats — both list the allowed keys after a
  // header word.
  var m = msg.match(/Allowed keys?:\s*([^.\n]+)/);
  if (!m) m = msg.match(/Allowed:\s*([^.\n]+)/);
  if (!m) return { ok: false, reason: "no-allow-list-in-error", message: msg };
  var keys = m[1].split(",").map(function (s) { return s.replace(/^\s+|\s+$/g, ""); }).filter(Boolean);
  return { ok: true, allowList: keys };
}

// Single-method signature like `b.module.method(opts)` — the only
// shape we know how to probe today. Multi-method (`b.X.a(opts) /
// b.X.b(opts)`) and positional-arg signatures (`b.X.method(arg, opts)`)
// fall through with a recorded reason.
function _isSingleOptsSignature(headingText) {
  return /^\s*(?:<code>\s*)?b\.[a-zA-Z0-9_.]+\(\s*opts\s*\??\s*\)/.test(headingText);
}

// ---- Opts diff ----
//
// For a primitive section that passes the single-opts-signature filter,
// diff the wiki opts keys against the lib's allow-list.
function _diffOptsKeys(b, headingText, optsCodeBlock) {
  if (!_isSingleOptsSignature(headingText)) {
    return { skipped: true, reason: "complex-signature" };
  }
  var fn = _resolveSignaturePath(b, headingText);
  if (!fn) {
    return { skipped: true, reason: "lib-fn-not-resolved" };
  }
  var probe = _probeAllowList(fn);
  if (!probe.ok) {
    return { skipped: true, reason: probe.reason };
  }
  var wikiKeys = _extractWikiOptsKeys(optsCodeBlock);
  if (!wikiKeys) {
    return { skipped: true, reason: "wiki-opts-block-unparseable" };
  }
  var libKeys = probe.allowList.slice();
  var addedInWiki = wikiKeys.filter(function (k) { return libKeys.indexOf(k) === -1; });
  var removedFromWiki = libKeys.filter(function (k) { return wikiKeys.indexOf(k) === -1; });
  return {
    skipped: false,
    wikiKeys: wikiKeys,
    libKeys: libKeys,
    addedInWiki:     addedInWiki,
    removedFromWiki: removedFromWiki,
  };
}

// ---- Post-boot pass helpers — example syntax / symbol / execution ----
//
// Each non-opts javascript example is checked through three lenses:
//
//   1. Syntax — V8 parses the code via vm.compileFunction, wrapped in
//      an async closure so top-level `await` is legal. Catches typos,
//      missing braces, dangling parens.
//
//   2. Symbol resolution — regex out every `b.X.Y` reference in the
//      example and walk the live framework to confirm each path
//      resolves. The wiki promises operator-callable surface; if a
//      reference doesn't resolve, the wiki documents an API the lib
//      no longer exposes (or never did) — drift the gate must catch.
//
//   3. Execution — best-effort. Most examples reference operator-
//      supplied stubs (req, res, db rows, an externalDb client, third-
//      party adapters). The harness binds a small fixed set of stubs
//      (req, res, env-shaped helpers); examples that need more are
//      classified "needs-context" and counted as illustrative-only,
//      not failed. Examples that reach the framework with bad arg
//      shapes still fail loud — that's the drift class operators want
//      caught.
//
// The wiki seeders are committed source — every example is content
// authored by the framework team. vm.compileFunction parses and
// invokes that content under a controlled lexical scope (no `require`,
// no globals beyond what we pass in). This is the standard Node
// pattern for sandboxed evaluation of trusted-source code.
var vm = require("node:vm");

function _decodeExampleEntities(code) {
  return code.replace(/&amp;/g, "&").replace(/&lt;/g, "<")
             .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
             .replace(/&#39;/g, "'");
}

function _checkExampleSyntax(code) {
  var asyncBody = "return (async () => {\n" + code + "\n})();";
  try {
    vm.compileFunction(asyncBody, ["b", "req", "res", "env"]);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}

function _frameworkPathsIn(code) {
  var paths = [];
  var seen = Object.create(null);
  var iter = code.matchAll(/\bb(\.[a-zA-Z_$][\w$]*)+/g);
  for (var m of iter) {
    var p = m[0];
    if (!seen[p]) { seen[p] = true; paths.push(p); }
  }
  return paths;
}

function _resolvePath(b, dotted) {
  var segs = dotted.split(".");
  if (segs[0] !== "b") return { resolved: false, missingAt: 0 };
  var cur = b;
  for (var i = 1; i < segs.length; i++) {
    if (cur === null || cur === undefined) {
      return { resolved: false, missingAt: i };
    }
    if (!Object.prototype.hasOwnProperty.call(Object(cur), segs[i])) {
      return { resolved: false, missingAt: i };
    }
    cur = cur[segs[i]];
  }
  return { resolved: true, value: cur };
}

function _checkExampleSymbols(b, code) {
  var paths = _frameworkPathsIn(code);
  var unresolved = [];
  for (var i = 0; i < paths.length; i++) {
    var p = paths[i];
    var r = _resolvePath(b, p);
    if (!r.resolved) unresolved.push(p);
  }
  return { ok: unresolved.length === 0, paths: paths, unresolved: unresolved };
}


// Spawn the run-example.js child with the example payload on stdin.
// The child boots a fresh framework instance, runs the example with
// the harness stubs in scope, and reports the outcome on stdout as
// JSON. One child per example = isolated framework state per run.
function _executeExampleForked(spec) {
  return new Promise(function (resolve) {
    var cp = require("node:child_process");
    var runner = path.join(__dirname, "run-example.js");
    var child = cp.spawn(process.execPath, [runner], {
      stdio: ["pipe", "pipe", "pipe"],
      env:   process.env,
    });
    var stdoutBuf = "";
    var stderrBuf = "";
    child.stdout.on("data", function (c) { stdoutBuf += c.toString("utf8"); });
    child.stderr.on("data", function (c) { stderrBuf += c.toString("utf8"); });
    child.on("close", function (code) {
      var SENTINEL = "<<<WIKI-VALIDATOR-OUTCOME>>>";
      var idx = stdoutBuf.lastIndexOf(SENTINEL);
      var result = null;
      if (idx >= 0) {
        var trailing = stdoutBuf.slice(idx + SENTINEL.length).trim();
        try { result = JSON.parse(trailing); }
        catch (_e) {
          result = {
            status: "harness-parse-error",
            error:  "outcome JSON malformed after sentinel",
            stdout: trailing.slice(0, 500),
            stderr: stderrBuf.slice(0, 500),
            exit:   code,
          };
        }
      } else {
        result = {
          status: "harness-no-outcome",
          error:  "child exited without writing the outcome sentinel",
          stdout: stdoutBuf.slice(-500),
          stderr: stderrBuf.slice(0, 500),
          exit:   code,
        };
      }
      resolve(result);
    });
    child.on("error", function (e) {
      resolve({ status: "harness-spawn-error", error: (e && e.message) || String(e) });
    });
    child.stdin.end(JSON.stringify(spec));
  });
}

async function runExamples(b) {
  var pages = _readPageBodies();
  var report = {
    total: 0,
    ran: 0,
    syntaxFailed:    [],
    symbolFailed:    [],
    executionFailed: [],
  };
  for (var p = 0; p < pages.length; p++) {
    var page = pages[p];
    var sections = _splitSections(page.body);
    for (var i = 0; i < sections.length; i++) {
      var s = sections[i];
      if (!_isPrimitiveHeading(s.text)) continue;
      var key = _exemptionKey(page.slug, s.text);
      if (EXEMPTIONS[key]) continue;
      var clusterContent = _clusterContent(sections, i);
      var blocks = _extractCodeBlocks(clusterContent);
      for (var b2 = 0; b2 < blocks.length; b2++) {
        var blk = blocks[b2];
        if (blk.looksLikeOpts) continue;
        if (blk.language !== "javascript") continue;
        report.total++;
        var decoded = _decodeExampleEntities(blk.content);

        var syn = _checkExampleSyntax(decoded);
        if (!syn.ok) {
          report.syntaxFailed.push({
            slug: page.slug, heading: s.text, error: syn.error,
          });
          continue;
        }

        var sym = _checkExampleSymbols(b, decoded);
        if (!sym.ok) {
          report.symbolFailed.push({
            slug: page.slug, heading: s.text, unresolved: sym.unresolved,
          });
          continue;
        }

        var exec = await _executeExampleForked({
          slug: page.slug, heading: s.text, code: decoded,
        });
        if (exec.status === "ran") {
          report.ran++;
        } else {
          report.executionFailed.push({
            slug: page.slug, heading: s.text,
            status:  exec.status,
            error:   exec.error || null,
            missing: exec.missing || null,
            stack:   exec.stack || null,
          });
        }
      }
    }
  }
  return report;
}

// ---- Validate ----

function _exemptionKey(slug, headingText) {
  return slug + ":" + headingText.slice(0, 50).toLowerCase().replace(/\s+/g, " ").trim();
}

// Accumulate the "cluster" content for a primitive section. The
// cluster is the full H2 subtree: H2 preface + every H3 inside it,
// up to (but not including) the next H2.
//
// Why H2-scoped: pages document related primitives as a single
// operator-readable unit under one H2 — "Passkeys" H2 covers
// startRegistration / verifyRegistration / startAuthentication /
// verifyAuthentication with the opts models per H3 and one merged
// example showing all four in flow. The cluster shares prose +
// example across siblings; each primitive H3 individually still
// needs its own opts model when the signature names opts.
//
// For top-level primitives that ARE H2s themselves, the cluster is
// the H2's own content + every H3 under it.
function _clusterContent(sections, startIdx) {
  var s = sections[startIdx];

  // Find the parent H2 (or self if startIdx is itself an H2).
  var parentIdx = startIdx;
  if (s.level === 3) {
    for (var k = startIdx - 1; k >= 0; k--) {
      if (sections[k].level === 2) { parentIdx = k; break; }
    }
    if (parentIdx === startIdx) parentIdx = -1; // no parent H2 above
  }

  var combined = "";
  if (parentIdx >= 0) {
    combined = sections[parentIdx].content;
    // Walk every section after the parent H2 until the next H2.
    for (var j = parentIdx + 1; j < sections.length; j++) {
      if (sections[j].level === 2) break;
      combined += "\n" + sections[j].raw + "\n" + sections[j].content;
    }
  } else {
    combined = s.content;
    for (var jj = startIdx + 1; jj < sections.length; jj++) {
      if (sections[jj].level <= s.level) break;
      combined += "\n" + sections[jj].raw + "\n" + sections[jj].content;
    }
  }
  return combined;
}

function _validatePage(page, opts) {
  opts = opts || {};
  var b = opts.framework || null;
  var sections = _splitSections(page.body);
  var violations = [];
  for (var i = 0; i < sections.length; i++) {
    var s = sections[i];
    if (!_isPrimitiveHeading(s.text)) continue;
    var key = _exemptionKey(page.slug, s.text);
    var exemptReason = EXEMPTIONS[key];
    var clusterContent = _clusterContent(sections, i);
    var blocks = _extractCodeBlocks(clusterContent);
    var hasOpts    = blocks.some(function (blk) { return blk.looksLikeOpts; });
    var hasExample = blocks.some(function (blk) {
      return !blk.looksLikeOpts && (blk.language === "javascript" || blk.language === "bash");
    });
    var hasProse   = _hasDescriptionProse(clusterContent);
    var needsOpts  = _signatureNamesOpts(s.text);

    var missing = [];
    if (needsOpts && !hasOpts) missing.push("opts-model");
    if (!hasProse)             missing.push("description-prose");
    if (!hasExample)           missing.push("example-code");

    // Opts diff — only when presence is satisfied AND the framework is
    // available for probing. We don't run the diff when presence
    // already failed; that report dominates and the diff would just
    // duplicate noise.
    var optsDiff = null;
    if (b && missing.length === 0 && hasOpts) {
      var optsBlock = blocks.find(function (blk) { return blk.looksLikeOpts; });
      if (optsBlock) {
        optsDiff = _diffOptsKeys(b, s.text, optsBlock.content);
      }
    }

    if (missing.length === 0) {
      // Presence OK. If opts diff found drift, surface it.
      if (optsDiff && !optsDiff.skipped &&
          (optsDiff.addedInWiki.length > 0 || optsDiff.removedFromWiki.length > 0)) {
        violations.push({
          slug:    page.slug,
          heading: s.text,
          missing: [],
          optsDiff: optsDiff,
          exempt:  !!exemptReason,
          reason:  exemptReason || null,
          key:     key,
        });
      }
      continue;
    }

    violations.push({
      slug:    page.slug,
      heading: s.text,
      missing: missing,
      optsDiff: optsDiff,
      exempt:  !!exemptReason,
      reason:  exemptReason || null,
      key:     key,
    });
  }
  return violations;
}

// ---- CLI entry ----

function run(opts) {
  opts = opts || {};
  var reportOnly = !!opts.reportOnly;
  // Load the framework module for opts-diff probing. Loading is safe
  // (it doesn't init vault/db); only factory-style functions need to
  // actually run, and they throw on the unknown probe key before any
  // state-touching path executes.
  var b = opts.framework;
  if (!b) {
    try { b = require(path.join(__dirname, "..", "..", "..", "index.js")); }
    catch (_e) { b = null; }
  }

  var pages = _readPageBodies();
  var allViolations = [];
  for (var i = 0; i < pages.length; i++) {
    var v = _validatePage(pages[i], { framework: b });
    for (var j = 0; j < v.length; j++) allViolations.push(v[j]);
  }

  var enforced = allViolations.filter(function (vi) { return !vi.exempt; });
  var exempted = allViolations.filter(function (vi) { return vi.exempt; });

  if (allViolations.length === 0) {
    console.log("[validate-primitive-sections] OK — every primitive section has heading + opts + prose + example, " +
      "and every probe-able opts model matches the lib allow-list");
    return 0;
  }

  if (enforced.length > 0) {
    var presence = enforced.filter(function (vi) { return vi.missing.length > 0; });
    var driftOnly = enforced.filter(function (vi) {
      return vi.missing.length === 0 && vi.optsDiff &&
        (vi.optsDiff.addedInWiki.length > 0 || vi.optsDiff.removedFromWiki.length > 0);
    });
    if (presence.length > 0) {
      console.error("[validate-primitive-sections] " + presence.length +
        " primitive section(s) missing required pieces:");
      for (var k = 0; k < presence.length; k++) {
        var u = presence[k];
        console.error("  " + u.slug + " :: " + u.heading);
        console.error("    missing: " + u.missing.join(", "));
        console.error("    key:     " + u.key);
      }
    }
    if (driftOnly.length > 0) {
      console.error("[validate-primitive-sections] " + driftOnly.length +
        " primitive section(s) with opts-key drift (wiki opts model out of sync with lib allow-list):");
      for (var dk = 0; dk < driftOnly.length; dk++) {
        var d = driftOnly[dk];
        console.error("  " + d.slug + " :: " + d.heading);
        if (d.optsDiff.addedInWiki.length > 0) {
          console.error("    wiki has but lib rejects:  " + d.optsDiff.addedInWiki.join(", "));
        }
        if (d.optsDiff.removedFromWiki.length > 0) {
          console.error("    lib accepts but wiki omits: " + d.optsDiff.removedFromWiki.join(", "));
        }
      }
    }
  }
  if (exempted.length > 0) {
    console.log("[validate-primitive-sections] " + exempted.length +
      " known-incomplete section(s) exempt (fix opportunistically):");
    for (var m = 0; m < exempted.length; m++) {
      var a = exempted[m];
      console.log("  " + a.slug + " :: " + a.heading);
      console.log("    missing: " + a.missing.join(", ") + "  — " + a.reason);
    }
  }

  if (reportOnly) return 0;
  return enforced.length > 0 ? 1 : 0;
}

module.exports = {
  run:                  run,
  runExamples:          runExamples,
  _readPageBodies:      _readPageBodies,
  _validatePage:        _validatePage,
  _splitSections:       _splitSections,
  _isPrimitiveHeading:  _isPrimitiveHeading,
  _signatureNamesOpts:  _signatureNamesOpts,
  _extractCodeBlocks:   _extractCodeBlocks,
  _extractWikiOptsKeys: _extractWikiOptsKeys,
  _frameworkPathsIn:    _frameworkPathsIn,
  _resolvePath:         _resolvePath,
  EXEMPTIONS:           EXEMPTIONS,
};

if (require.main === module) {
  var reportOnly = process.argv.indexOf("--report") !== -1;
  process.exit(run({ reportOnly: reportOnly }));
}
