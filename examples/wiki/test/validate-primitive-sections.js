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
  "reliability:b.retry.withretry(fn, opts)":
    "compound section that demonstrates retry + circuit-breaker composition — `guarded` references the breaker example's local",
  "compliance-patterns:b.security.assertproduction(opts)":
    "example references process.env.WIKI_ADMIN_PASSWORD (operator-side env) and asserts boot-time posture",
  "safe-parsers:b.filetype.detect(buffer, opts?)":
    "example references uploadedBuffer (per-request value from a route handler — operator-side)",
  "safe-parsers:b.filetype.assertoneof(buffer, allowlist, opts?)":
    "example references uploadedBuffer + res (per-request values — operator-side)",
  "auth:b.auth.password.policy(opts)":
    "example references user.passwordHashHistory / user.passwordSetAt (per-account state read from DB — operator-side)",
  "observability:b.audit.safeemit(event)":
    "example shows compound emission in a route handler — references operator-side `body` from req parsing",
  "network-config:b.network.ntp.bootcheck(opts) / setthresholds(opts":
    "boot-check example dials real NTP/UDP — operator-network-only path",
  "network-config:b.network.ntp.nts.query(opts) — authenticated ntp":
    "NTS query negotiates with a live NTS-KE server over TLS — operator-network-only path",
  "network-config:b.network.dns.lookup(host, opts?) / setservers / s":
    "DNS examples resolve real hostnames against an operator-pinned resolver — sandbox can't simulate",
  "network-config:b.network.proxy.fromenv() / set(opts) / shouldprox":
    "proxy example calls outbound https through a tunnel that the harness can't reach",
  "network-config:b.network.tls.addca(pemorpath, opts?) / addcabundl":
    "addCa example loads operator-supplied PEM file from disk and dials internal HTTPS — operator-network-only",
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
// Match either b.X(args) (top-level function) OR b.X.Y(args)+ (namespaced
// method). The trailing ( is the disambiguator — bare prose mentions of
// `b.X` without parens don't match (those are operator-facing references,
// not signature headings).
var PRIMITIVE_SIGNATURE_RE = /^\s*(?:<code>\s*)?b\.[a-z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*\s*\(/;

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

  // Gather every executable example into a queue first; do the cheap
  // syntax + symbol checks inline (no forks needed). The expensive
  // step is the forked runtime — that runs in parallel batches.
  var pending = [];
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
        pending.push({ slug: page.slug, heading: s.text, code: decoded });
      }
    }
  }

  // Parallel execution. SMOKE_PARALLEL respected (capped at 64 to
  // match the smoke runner) — sequential mode (`SMOKE_PARALLEL=1`)
  // available as a fallback for diagnosis.
  var rawN = parseInt(process.env.SMOKE_PARALLEL || "1", 10);
  var concurrency = (isFinite(rawN) && rawN > 0) ? Math.min(rawN, 64) : 1;
  var queueIdx = 0;
  async function _worker() {
    while (queueIdx < pending.length) {
      var spec = pending[queueIdx++];
      var exec = await _executeExampleForked(spec);
      if (exec.status === "ran") {
        report.ran++;
      } else {
        report.executionFailed.push({
          slug: spec.slug, heading: spec.heading,
          status:  exec.status,
          error:   exec.error || null,
          missing: exec.missing || null,
          stack:   exec.stack || null,
        });
      }
    }
  }
  var workers = [];
  for (var w = 0; w < Math.min(concurrency, pending.length); w++) {
    workers.push(_worker());
  }
  await Promise.all(workers);
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

// ---- Missing-section enumeration ----
//
// The earlier validator only checked that EXISTING wiki sections have
// the four required pieces (heading + opts + prose + example). It did
// NOT catch the case where an operator-facing primitive on `b.*`
// has NO documented section at all. This walker enumerates `b.*`,
// applies a skip-list for non-primitive surface (constants, internal
// catalogs, frameworkError class registry, lazyRequire helper, etc.),
// and reports every undocumented primitive.
//
// Two-level enumeration: every top-level key on `b.*` is checked, AND
// every sub-key on top-level namespace objects (b.middleware.*,
// b.auth.*, b.auditSign.*, etc.). Without the second level, new
// methods added to an already-documented namespace (e.g.
// b.middleware.requireMtls landing under the existing middleware page)
// are invisible to the gate because the namespace itself is in the
// "documented" set. BX_SKIP and UNDOCUMENTED_BACKLOG accept both
// bare names ("auth") and qualified names ("auth.accessLock") so a
// blanket namespace skip and a per-method opt-out are both expressible.
//
// Pre-v0.7.31 backlog: primitives that pre-existed without a wiki
// section live in UNDOCUMENTED_BACKLOG below with a one-line reason —
// they're visible warnings, not gate failures, until backfilled. New
// primitives shipped from v0.7.31 forward MUST either land with a
// wiki section OR get added to UNDOCUMENTED_BACKLOG explicitly.

// Top-level keys on `b.*` that are NOT primitives — skipped entirely.
// Sub-key entries (`auth.acr` etc.) skip a single method when the
// parent namespace is being recursively enumerated.
var BX_SKIP = new Set([
  // Top-level non-primitive surface.
  "constants",         // compile-time scale helpers, not callable
  "frameworkError",    // class catalog (typed errors), not a primitive
  "_modules",          // raw-module advanced access
  "_internalForTest",  // internal test plumbing
  "testing",           // test helpers (b.testing.bodyReq etc. — pages document via testing.js page)
  "lazyRequire",       // build-time helper for circular-dep modules
  "validateOpts",      // build-time helper used inside primitives
  "cliHelpers",        // CLI subcommand plumbing
  "parsers",           // namespace; sub-modules documented under safe-parsers
  "logStream",         // documented under observability page
  "events",            // documented under observability page
  "redact",            // documented under observability page
  "lib",               // raw module access
  // Sub-key non-primitive surface (parent.child form). Used by the
  // BX_RECURSE walker to ignore sub-keys that are data tables / getters
  // / constants rather than operator-facing primitives.
  "auth.acr",                            // ACR vocabulary table (constants only, no callable surface)
  "auditSign.DEFAULT_SIGNING_ALG",       // constant string
  "auditSign.SUPPORTED_SIGNING_ALGS",    // constant array
  "auditSign.ENV_PASSPHRASE",            // constant string
  "auditSign.ENV_PASSPHRASE_FILE",       // constant string
  "auditSign.ENV_PASSPHRASE_SRC",        // constant string
  "auditSign.getMode",                   // getter, not a primitive
  "auditSign.getAlgorithm",              // getter, not a primitive
  "auditSign.getPublicKey",              // getter, not a primitive
  "auditSign.getPublicKeyFingerprint",   // getter, not a primitive

  // Internal helpers, leaf utilities, getters, build-time tooling,
  // and bare module namespaces — not operator-facing primitives.
  // Each carries a per-entry rationale.
  "a2a.verifyCard", // internal helper used by b.a2a primitive for agent-card verification; not a standalone operator API
  "aiPref.parseHeader", // header-parser helper used internally by aiPref middleware; consumers use the middleware not the parser
  "aiPref.refusePaidCrawl", // internal predicate used by aiPref middleware to enforce paid-crawl refusal; operator-facing surface is the middleware
  "apiKey.parseFormat", // string-parsing helper used inside apiKey verify/issue paths; not invoked directly by operators
  "apiSnapshot", // module namespace; the export shape is the four sub-functions, not the module object itself
  "apiSnapshot.capture", // build-time tooling under scripts/refresh-api-snapshot.js; not an operator runtime API
  "apiSnapshot.compare", // build-time tooling used by scripts/check-api-snapshot.js; CI gate, not operator surface
  "apiSnapshot.formatDiff", // internal pretty-printer for snapshot diff output; build tooling helper
  "apiSnapshot.read", // build-time fs helper for snapshot.json; not an operator API
  "apiSnapshot.write", // build-time fs helper for snapshot.json; not an operator API
  "appShutdown.pidLock", // internal pid-lock helper used by app.shutdown; operator interacts via b.appShutdown only
  "audit.emit", // internal hot-path emitter; operator-facing audit surface is audit.safeEmit + receiver wiring
  "audit.verifyCheckpoints", // internal helper used by auditChain.verifyChain; operators use the verifyChain API
  "auditChain", // module namespace; methods documented individually
  "auditChain.canonicalize", // RFC 8785 JCS helper used inside computeRowHash; not a standalone operator API
  "auditChain.computeRowHash", // internal row-hash builder used by chainWriter; operators interact via verifyChain/getChainTip
  "auditSign", // module namespace; signing methods documented individually
  "auditSign.init", // internal lifecycle hook called once at framework boot; not an operator runtime API
  "auditSign.sign", // internal signer invoked by audit pipeline; operator surface is audit.safeEmit + verify
  "backup.localStorage", // factory for the default local-fs backup storage backend; wired automatically via b.backup() opts
  "backup.recommendedFiles", // constant list consumed by b.backup() default config; not a standalone primitive
  "backupBundle", // module namespace; the create method is the operator-facing entry
  "backupCrypto", // module namespace; internal crypto layer used by backupBundle, never called directly
  "backupCrypto.checksum", // internal checksum helper used by backupBundle.create; not a standalone API
  "backupCrypto.decryptWithPassphrase", // internal decryption primitive invoked by restoreBundle; operator surface is restoreBundle
  "backupCrypto.deriveKey", // internal Argon2id-derivation helper used by backupCrypto encrypt/decrypt; not exposed
  "backupCrypto.encryptWithFreshSalt", // internal encryption primitive used by backupBundle.create; not a standalone API
  "backupCrypto.encryptWithPassphrase", // internal encryption primitive used by backupBundle.create; not a standalone API
  "backupManifest", // module namespace; only consumed inside backupBundle/restoreBundle pipeline
  "backupManifest.create", // internal manifest builder used by backupBundle.create; operators don't call directly
  "backupManifest.parse", // internal parser used by restoreBundle.inspect; operator surface is restoreBundle
  "backupManifest.serialize", // internal serializer used by backupBundle.create; not a standalone API
  "backupManifest.validate", // internal manifest validator used by restoreBundle.extract; not a standalone API
  "bundler", // module namespace; create is the operator entry
  "bundler.engine", // internal module-resolution engine used by bundler.create; not exposed
  "chainWriter", // module namespace; create is the only export shape
  "circuitBreaker", // module namespace; documented as the create() factory
  "circuitBreaker.CircuitBreaker", // underlying class; the operator-facing factory is circuitBreaker.create()
  "cli", // module namespace; main is the entry point
  "cli.main", // internal CLI entry invoked only by bin/blamejs; not called from operator code
  "clusterStorage", // module namespace; SQL helper layer used by frameworkSchema, not a standalone operator API
  "clusterStorage.execute", // internal SQL executor used by frameworkSchema/auditChain; operators use the higher-level db primitives
  "clusterStorage.executeAll", // internal multi-row SQL executor used inside framework storage; not exposed to operators
  "clusterStorage.executeOne", // internal single-row SQL executor used inside framework storage; not exposed
  "clusterStorage.placeholderize", // internal SQL-placeholder converter used by clusterStorage.execute; not standalone
  "clusterStorage.resolveTables", // internal table-prefix resolver used by frameworkSchema; not standalone
  "clusterStorage.tableName", // internal table-name builder shared with frameworkSchema; not standalone
  "config.coerce", // internal type-coercion helper used inside config.create; not a standalone operator API
  "cookies.serialize", // internal Set-Cookie string builder used by middleware/session; operators use middleware.cookies
  "credentialHash.inspect", // introspection helper for stored hashes; used internally by needsRehash, low operator demand
  "cryptoField.clearForTest", // test-only reset hook; never called from operator code
  "db.exec", // low-level SQL execute used inside db.js plumbing; operator-facing query surface is db.query/db.run
  "db.getDataResidency", // internal getter consumed by compliance posture; not a standalone runtime API
  "db.getDbPath", // internal path getter used by backup recommendedFiles; trivial accessor
  "db.getTableMetadata", // internal schema-introspection helper used by frameworkSchema/migrations; not operator-facing
  "dev", // module namespace; create is the entry
  "dev.create", // internal dev-only helper toggled by NODE_ENV; not an operator-runtime API
  "dsr.dbTicketStore", // default backend factory wired via b.dsr.create() opts; operators don't construct directly
  "dsr.memoryTicketStore", // in-memory test backend for b.dsr; not a production-recommended standalone API
  "externalDb.adapters", // internal adapter map (pg/mysql/sqlite) consumed by externalDb.Pool; not directly addressable
  "externalDb.read", // internal read-side wrapper used by Pool; operator surface is the Pool/cluster wiring
  "externalDb.write", // internal write-side wrapper used by Pool; operator surface is the Pool/cluster wiring
  "flag.cache", // internal cache module wired into flag evaluation; not a standalone operator API
  "flag.context", // internal evaluation-context shape consumed by flag.targeting; not standalone
  "flag.providers", // internal provider registry used by flag evaluation; operators register via b.flag opts
  "flag.targeting", // internal targeting-rule evaluator used by flag.evaluate; not standalone
  "forms.escapeAttribute", // string-escape helper used inside forms.render; operator-facing surface is the form render APIs
  "forms.escapeHtml", // string-escape helper used inside forms.render; operator-facing surface is the form render APIs
  "forms.verifyCsrfToken", // internal CSRF-token verifier called by forms middleware; operators use the middleware
  "frameworkSchema", // module namespace; ensureSchema is invoked once at boot, no operator surface
  "frameworkSchema.ensureSchema", // internal boot-time schema bootstrapper called by app.create; operators don't invoke directly
  "frameworkSchema.tableName", // internal table-prefix accessor; trivial helper
  "handlers", // module namespace; documented under routing as the request-handler factory
  "handlers.create", // internal handler-pipeline builder used by router; operators wire handlers through the router API
  "htmlBalance.checkSafe", // tag-balance helper used inside guardHtml/guardMarkdown; not a standalone operator API
  "log.boot", // boot-time logger used by app.create; operator-facing log surface is log.create + the request log helpers
  "log.makeViaOrFallback", // internal ALS-with-fallback helper used inside log.create; not exposed
  "mailBounce.vendors", // internal vendor-format registry consumed by mailBounce.parse; not standalone
  "metrics.tap", // internal observation hook used by metrics.create; operator surface is the create + emit APIs
  "mtlsCa.parseGeneration", // version-string parser used inside CA generation; not a standalone operator API
  "mtlsEngine", // module namespace; engine implementation behind b.mtls primitive
  "mtlsEngine.algorithmEnvelope", // internal alg-envelope builder used by signClientCert; not standalone
  "mtlsEngine.generateCa", // internal CA-generation primitive used by b.mtls; operators call the b.mtls factory
  "mtlsEngine.generateCrl", // internal CRL-generation primitive used by b.mtls; operators call the b.mtls factory
  "mtlsEngine.packageP12", // internal PKCS#12 packager used by b.mtls; not standalone
  "mtlsEngine.signClientCert", // internal client-cert signer used by b.mtls; operators call the b.mtls factory
  "nonceStore", // module namespace; create is the operator entry
  "objectStore", // module namespace; documented under object-store wiki page already
  "objectStore.buildBackend", // internal backend-factory dispatch used inside objectStore.create; operators pass opts and don't call buildBackend
  "observability.baggage", // internal W3C baggage propagation helper used by tracing; operator surface is observability.event/safeEvent
  "observability.otlpExporter", // internal OTLP exporter wired via b.tracing config; operators don't construct directly
  "observability.safeEvent", // alias of observability.event; documented under the parent observability section
  "observability.setTap", // internal test-tap hook used by smoke tests; not operator-facing
  "outbox", // module namespace; create is the operator entry
  "permissions.match", // internal match helper used by access-control rule evaluation; operators use the policy DSL
  "pqcAgent.createHttp", // internal http-agent factory wired via b.httpClient PQC opt; operators flip the opt, don't construct
  "pqcGate.clientHelloHasPQC", // internal TLS clientHello inspector used by the PQC gate middleware; not a standalone operator API
  "protocolDispatcher", // module namespace; create is the operator entry
  "pubsub", // module namespace; create is the operator entry, documented under queue-cache
  "render.create", // internal render-context factory used by router; operators use res.json/res.text/res.redirect helpers
  "restoreBundle", // module namespace; extract/inspect are the operator-facing methods
  "restoreRollback", // module namespace; rollback/swap/list/purge are the operator-facing methods
  "retry.backoffDelay", // internal backoff-delay calculator used by retry.create; operator surface is the create API
  "retry.isRetryable", // internal predicate used by retry.create; operators configure via opts.shouldRetry
  "router", // module namespace; documented under routing wiki page
  "router.Router", // underlying class; operator-facing factory is the b.router/app.router export
  "router.serveStatic", // internal alias to b.staticServe used by router; operators call b.staticServe directly
  "safeBuffer.hasCrlf", // byte-classification helper used inside safe-parsers; not a standalone operator API
  "safeBuffer.isHex", // byte-classification helper used inside safe-parsers; not a standalone operator API
  "safeBuffer.stripCrlf", // byte-stripping helper used inside safe-parsers; not a standalone operator API
  "safeBuffer.stripTrailingHspace", // byte-stripping helper used inside safe-parsers/header parsing; not standalone
  "safeBuffer.toBuffer", // trivial coercion helper used inside parsers; not a standalone operator API
  "safeSchema.nullable", // schema combinator already covered by the parent safeSchema page; trivial helper
  "safeSchema.oneOf", // schema combinator already covered by the parent safeSchema page; trivial helper
  "safeSchema.undefined_", // trivial leaf type combinator already covered under the parent schema page
  "safeSchema.unknown", // trivial leaf type combinator already covered under the parent schema page
  "safeSql.assertOneOf", // internal allow-list assertion helper used inside safeSql.quoteIdentifier; trivial guard
  "safeSql.quoteIdentifier", // leaf SQL-identifier quoter used inside the safeSql primary API; trivial helper
  "safeSql.quoteQualified", // leaf qualified-identifier quoter used inside the safeSql primary API; trivial helper
  "scheduler.nextBaselineFire", // internal next-fire calculator used by b.scheduler; operators use the scheduler API
  "scheduler.nextCronFire", // internal cron next-fire calculator used by b.scheduler; operators use the scheduler API
  "scheduler.parseCron", // internal cron-spec parser used by b.scheduler; operators pass cron strings to the scheduler API
  "seeders", // module namespace; create is the entry; primarily test/dev fixture loader
  "seeders.create", // test/dev fixture loader used in examples/wiki seed scripts; not a production operator API
  "template", // module namespace; render is the operator-facing call
  "template.create", // internal template-context factory used by template.render; operators call render with opts
  "template.escapeHtml", // string-escape helper used inside template.render; operator-facing surface is the render API
  "tracing", // module namespace; documented under observability wiki page
  "tracing.tap", // internal test-tap hook used by smoke tests; not operator-facing
  "uuid.isValid", // trivial validator helper used inside b.uuid; the parent uuid section covers it
  "uuid.parse", // trivial parser helper used inside b.uuid; the parent uuid section covers it
  "vaultPassphraseOps", // module namespace; methods documented individually under crypto-vault
  "vaultPassphraseOps.preflightRotatable", // internal preflight check called by vaultPassphraseOps.rotate; not a standalone operator entry
  "vaultPassphraseOps.preflightSealable", // internal preflight check called by vaultPassphraseOps.seal; not a standalone operator entry
  "vaultPassphraseOps.preflightUnsealable", // internal preflight check called by vaultPassphraseOps.unseal; not a standalone operator entry
  "vaultPassphraseSource", // module namespace; documented as the passphrase-source factories under crypto-vault
  "vaultPassphraseSource.getPassphrase", // internal resolution helper that dispatches to the from* sources; operators construct sources, not call this directly
  "vaultPassphraseSource.sourceKind", // trivial discriminator getter on the source object; not a standalone API
  "vaultRotate", // module namespace; rotate/verify are the operator-facing methods
  "vaultRotate.formatValidationResult", // internal pretty-printer for rotate validation output; not a standalone API
  "vaultRotate.validateSchemaMatch", // internal schema-match check used inside vaultRotate.rotate; not standalone
  "vaultWrap", // module namespace; wrap/unwrap are the operator-facing methods
  "vaultWrap.buildHeader", // internal header builder used inside vaultWrap.wrap; not a standalone operator API
  "vaultWrap.deriveWrappingKey", // internal HKDF wrapping-key derivation used inside vaultWrap; not standalone
  "vaultWrap.parseHeader", // internal header parser used inside vaultWrap.unwrap; not standalone
  "version", // trivial version-string export read from package.json; not a primitive
  "websocket.FrameParser", // underlying frame-parser class used by websocket.WebSocketConnection; operators use the connection API
  "websocket.WebSocketConnection", // underlying connection class; operator-facing surface is the b.websocket factory and event handlers
  "websocket.isOriginAllowed", // internal origin-check predicate used by validateUpgradeRequest; not a standalone API
  "websocket.serializeFrame", // internal frame serializer used by WebSocketConnection.send; not a standalone API
  "websocket.validateUpgradeRequest", // internal Upgrade-handshake validator used by the websocket server bootstrap; not standalone
]);


// Pre-v0.7.31 primitives without a dedicated wiki section. Each entry
// names the page it SHOULD be documented under (or notes the reason
// for the gap). Backfill opportunistically; new primitives don't get
// added here without an explicit reason.
var UNDOCUMENTED_BACKLOG = {
  "pqcSoftware.DEFAULT_HASH_SIG":    "constant/data table; referenced from parent primitive docs instead of a standalone page",
  "pqcSoftware.DEFAULT_KEM":         "constant/data table; referenced from parent primitive docs instead of a standalone page",
  "pqcSoftware.DEFAULT_LATTICE_SIG": "constant/data table; referenced from parent primitive docs instead of a standalone page",
  "security.DEFAULT_RESOLVERS":      "constant/data table; referenced from parent primitive docs instead of a standalone page",
  "budr.list":                       "BUDR breach-disclosure registry — wiki page belongs under compliance-patterns; backfill pending",
  "consent.history":                 "consent ledger query — wiki page belongs under access-control alongside consent.grant; backfill pending",
  "consent.isGranted":               "consent ledger predicate — wiki page belongs under access-control alongside consent.grant; backfill pending",
  "consent.withdraw":                "consent withdrawal API — wiki page belongs under access-control alongside consent.grant; backfill pending",
  "contentCredentials.verify":       "C2PA verifier — wiki page belongs under compliance-patterns; backfill pending",
  "darkPatterns.attest":             "FTC dark-patterns attestation — wiki page belongs under compliance-patterns; backfill pending",
  "darkPatterns.recordCancelFlow":   "FTC click-to-cancel recorder — wiki page belongs under compliance-patterns; backfill pending",
  "db.close":                        "framework db lifecycle hook — wiki page belongs under database; backfill pending",
  "db.getStreamLimit":               "internal accessor surfaced for db-query.js stream-limit lookup; not operator-facing",
  "safeJsonPath":                    "namespace — covered by the merged validateExpression/Pointer/Key/Containment heading on database wiki",
  "safeJsonPath.validatePointer":    "covered by the merged b.safeJsonPath heading on the database wiki",
  "safeJsonPath.validateKey":        "covered by the merged b.safeJsonPath heading on the database wiki",
  "safeJsonPath.validateContainment":"covered by the merged b.safeJsonPath heading on the database wiki",
  "db.integrityMonitor":             "db integrity-monitor primitive — wiki page belongs under database; backfill pending",
  "externalDb.Pool":                 "external-db connection pool factory — wiki page belongs under database alongside externalDb.create; backfill pending",
  "iabMspa.checkOptOut":             "IAB MSPA opt-out check — wiki page belongs under compliance-patterns; backfill pending",
  "iabTcf.checkVendor":              "IAB TCF v2.3 vendor consent check — wiki page belongs under compliance-patterns; backfill pending",
  "mail.toUnicode":                  "EAI/SMTPUTF8 punycode->unicode helper — wiki page belongs under mail; backfill pending",
  "migrations":                      "schema-migrations namespace — wiki page belongs under database; backfill pending",
  "migrations.create":               "schema-migrations factory — wiki page belongs under database; backfill pending",
  "tcpa10dlc.revoke":                "TCPA 10DLC consent revocation — wiki page belongs under compliance-patterns; backfill pending",
  "fda21cfr11.checkGxpAudit":        "non-throwing predicate counterpart to assertGxpAudit — covered by the parent posture section's prose",
  "auditTools.exportAudit":          "format-dispatcher leaf — documented under b.audit.export in observability",
  "auditTools.exportCadf":           "CADF leaf form invoked through b.audit.export({ format: 'cadf' }); covered in the audit-export section",
  "compliance.postureDefault":       "internal posture-default lookup consumed by primitives (backup, retention); not a standalone operator API",
  "backup.verifyManifestSignature":  "documented under b.backupBundle.verifyManifestSignature in backup-restore — same primitive surfaced under both namespaces",
  // F-POSTURE-1 cascade hooks — primitives expose applyPosture(name) +
  // getActivePosture()/activePosture() so b.compliance.set can install
  // the posture across every participating subsystem in one call. The
  // operator-facing API is b.compliance.set; the per-primitive hooks
  // are documented in the parent compliance.set wiki section under
  // compliance-patterns rather than as standalone primitive pages.
  "retention.applyPosture":          "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "retention.activePosture":         "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "audit.applyPosture":              "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "audit.activePosture":             "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "db.applyPosture":                 "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "db.getActivePosture":             "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "cryptoField.applyPosture":        "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  "cryptoField.getActivePosture":    "F-POSTURE-1 cascade hook — invoked by b.compliance.set; documented under b.compliance.set in compliance-patterns",
  // cryptoField column-residency + per-row-key surface — operator-
  // facing helpers carried alongside b.cryptoField.declareColumnResidency
  // (covered on the compliance-patterns wiki); standalone pages pending
  // backfill alongside the rest of the column-residency family.
  "cryptoField.getColumnResidency":     "documented inline alongside b.cryptoField.declareColumnResidency in compliance-patterns; backfill pending",
  "cryptoField.assertColumnResidency":  "documented inline alongside b.cryptoField.declareColumnResidency in compliance-patterns; backfill pending",
  "cryptoField.hasPerRowKey":           "documented inline alongside b.cryptoField.declarePerRowKey in compliance-patterns; backfill pending",
  "cryptoField.materializePerRowKey":   "documented inline alongside b.cryptoField.declarePerRowKey in compliance-patterns; backfill pending",
  "cryptoField.destroyPerRowKey":       "documented inline alongside b.cryptoField.declarePerRowKey in compliance-patterns; backfill pending",
  "cryptoField.clearResidencyForTest":  "test-only helper paralleling clearForTest; not operator-facing",
  "subject.eraseHard":                  "subject-erase-hard — wiki page belongs under compliance-patterns alongside b.subject.erase; backfill pending",
  "sandbox":                            "sandbox namespace — wiki page belongs under ops-hardening alongside b.sandbox.run; backfill pending",
  "sandbox.run":                        "sandbox.run primitive — wiki page belongs under ops-hardening; backfill pending",
};

function _enumerateBxPrimitives(b, pages) {
  var keys = Object.keys(b).filter(function (k) { return k[0] !== "_"; });

  // Build a set of every documented primitive signature by walking
  // the wiki page bodies + extracting every primitive heading.
  var documented = new Set();
  for (var p = 0; p < pages.length; p += 1) {
    var sections = _splitSections(pages[p].body);
    for (var s = 0; s < sections.length; s += 1) {
      if (!_isPrimitiveHeading(sections[s].text)) continue;
      // Extract the leading b.X.Y or b.X path from the signature.
      var m = sections[s].text.match(/b\.([a-zA-Z][a-zA-Z0-9_]*)(?:\.([a-zA-Z][a-zA-Z0-9_]*))?/);
      if (!m) continue;
      documented.add(m[1]);                                    // top-level
      if (m[2]) documented.add(m[1] + "." + m[2]);             // method-level
    }
  }

  var undocumented = [];
  for (var k = 0; k < keys.length; k += 1) {
    var name = keys[k];
    var topSkipped = BX_SKIP.has(name);
    if (!topSkipped && !documented.has(name) && !UNDOCUMENTED_BACKLOG[name]) {
      undocumented.push(name);
    }

    // Recurse one level into top-level namespaces. We still recurse
    // when the parent is in UNDOCUMENTED_BACKLOG (the parent has a
    // known gap, but new methods landing under it must surface
    // separately). We DON'T recurse when the parent is in BX_SKIP —
    // BX_SKIP means "not operator-facing surface at all."
    if (topSkipped) continue;
    var val = b[name];
    if (!val || typeof val !== "object" || Array.isArray(val)) continue;

    var subKeys = Object.keys(val).filter(function (sk) { return sk[0] !== "_"; });
    for (var s2 = 0; s2 < subKeys.length; s2 += 1) {
      var sub = subKeys[s2];
      var qualified = name + "." + sub;
      if (BX_SKIP.has(qualified)) continue;
      if (/Error$/.test(sub)) continue;

      // Only flag operator-facing surface. A sub-key is operator-
      // facing if its value is a function (factory / direct primitive)
      // OR a sub-module object exposing at least one callable. Bare
      // data tables, vocabularies, and class instances aren't
      // primitive-shaped and stay invisible to the gate.
      var subVal = val[sub];
      var isFn = typeof subVal === "function";
      var isModule = subVal && typeof subVal === "object" && !Array.isArray(subVal) &&
        Object.keys(subVal).some(function (mk) { return typeof subVal[mk] === "function"; });
      if (!isFn && !isModule) continue;

      if (documented.has(qualified)) continue;
      if (UNDOCUMENTED_BACKLOG[qualified]) continue;
      undocumented.push(qualified);
    }
  }
  return undocumented;
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

  // Missing-section enumeration. Every operator-facing primitive on
  // b.* must either have a wiki section (signature-prefixed heading)
  // OR be in BX_SKIP / UNDOCUMENTED_BACKLOG. New primitives added
  // without either path fail the gate.
  var undocumented = b ? _enumerateBxPrimitives(b, pages) : [];

  var enforced = allViolations.filter(function (vi) { return !vi.exempt; });
  var exempted = allViolations.filter(function (vi) { return vi.exempt; });

  if (allViolations.length === 0 && undocumented.length === 0) {
    console.log("[validate-primitive-sections] OK — every primitive section has heading + opts + prose + example, " +
      "every probe-able opts model matches the lib allow-list, and every operator-facing b.* primitive has a documented section");
    return 0;
  }
  if (undocumented.length > 0) {
    console.error("[validate-primitive-sections] " + undocumented.length +
      " operator-facing b.* primitive(s) lack a documented wiki section:");
    for (var ui = 0; ui < undocumented.length; ui += 1) {
      console.error("  b." + undocumented[ui] + " — add a wiki section (signature-prefixed heading + opts model + " +
                    "description + example) OR add to UNDOCUMENTED_BACKLOG with a one-line reason in " +
                    "examples/wiki/test/validate-primitive-sections.js");
    }
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
  return (enforced.length > 0 || undocumented.length > 0) ? 1 : 0;
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
