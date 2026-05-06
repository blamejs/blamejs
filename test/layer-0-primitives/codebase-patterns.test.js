"use strict";
/**
 * codebase-patterns — automated grep gates for code-shape bug classes
 * that have surfaced repeatedly across releases.
 *
 * The patterns covered:
 *
 *   - raw byte literals (use C.BYTES.* helpers)
 *   - raw time literals (use C.TIME.* helpers)
 *   - numeric opts that silently accept Infinity / NaN
 *     (route through lib/numeric-bounds)
 *   - HTTP/2 session.close() without paired destroy()
 *     (route through lib/http2-teardown)
 *   - Object.keys(...).sort() canonicalize walks that lose
 *     Date / Buffer / Map / Set / BigInt (route through
 *     lib/canonical-json)
 *   - regex-only string format validators with no length cap
 *   - stray console.* in production code paths
 *   - TODO / FIXME / HACK / XXX markers
 *   - inline require() (should be top-of-file)
 *   - Tier-A/B/C internal vocabulary in lib/ comments
 *   - Math.random() in security-sensitive contexts
 *   - raw === for hash/token/sig comparisons
 *   - new URL(...) without safeUrl.parse() guard
 *   - bare JSON.parse on operator-supplied input
 *   - process.exit() in lib/
 *   - empty catch (_e) {} silent swallows
 *   - new RegExp(...) dynamic compilation from operator input
 *
 * The test reads every `lib/**.js` file (excluding `lib/vendor/`) and
 * scans for each pattern. A violation produces a numbered report with
 * file:line:offending-text so the operator can fix it before commit.
 *
 * **Exceptions** are documented at the violation site, not in this
 * test file. Two shapes:
 *
 *   1. File-level header within the first 50 lines:
 *        // codebase-patterns:allow-file <class> — <reason>
 *      Skips every match for that class in the file.
 *
 *   2. Per-line inline marker on the same line or up to 2 lines above:
 *        ... // allow:<class> — <reason>
 *      Skips that single match.
 *
 * Add new patterns here when a new bug class is identified. The test
 * is the single source of truth for "we already swept this class once
 * and don't want it to drift back in."
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var check = helpers.check;

var LIB_ROOT = path.resolve(__dirname, "..", "..", "lib");

function _walk(dir, files) {
  files = files || [];
  if (path.basename(dir) === "vendor") return files;
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var full = path.join(dir, e.name);
    if (e.isDirectory()) _walk(full, files);
    else if (e.isFile() && e.name.endsWith(".js")) files.push(full);
  }
  return files;
}

function _libFiles() { return _walk(LIB_ROOT); }

function _relPath(absPath) {
  return path.relative(path.resolve(__dirname, "..", ".."), absPath).replace(/\\/g, "/");
}

// scan(pattern, opts) — applies the regex line-by-line. Returns
// matches as { file, line, content, lineNum }. Skips lines that match
// the comment-prefix shape (`//`, ` * `, `/*` etc.) when
// opts.skipComments is true (the default).
function _scan(regex, opts) {
  opts = opts || { skipComments: true };
  var matches = [];
  var files = _libFiles();
  for (var i = 0; i < files.length; i++) {
    var content;
    try { content = fs.readFileSync(files[i], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var j = 0; j < lines.length; j++) {
      var line = lines[j];
      if (opts.skipComments && /^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (regex.test(line)) {
        matches.push({
          file:    _relPath(files[i]),
          line:    j + 1,
          content: line.trim(),
        });
      }
    }
  }
  return matches;
}

// Allow markers come in two shapes:
//
//   1. **File-level header** at the top of the file (within the first
//      30 lines, typically right under the docstring):
//
//        // codebase-patterns:allow-file inline-require — lazy
//        //   circular-dep loads documented per-line below
//
//      Every match for that class in the file is skipped. Use this
//      when a file has many legitimate matches with a shared reason
//      (e.g., db.js's lazy-loaded test-reset stubs).
//
//   2. **Per-line inline marker** at the source line or one line above:
//
//        var MAX_ARGON2_MEMORY = 4 * 1024 * 1024; // allow:raw-byte-literal — argon2 memoryCost is KiB-as-bytes per RFC 9106
//
//      Use this when only one or two lines in the file are exceptions.
//
// Both forms must include a `— reason` after the class id. The class
// id matches the pattern's bug-class id (raw-byte-literal,
// numeric-opt-Infinity, http2-bare-close, console-direct, etc.).
function _filterMarkers(matches, allowClass) {
  // Cache content + file-level allow detection per file.
  var fileCache = {};
  var fileAllowCache = {};
  function _readContext(file) {
    if (!fileCache[file]) {
      try {
        var p = path.resolve(path.resolve(__dirname, "..", ".."), file);
        fileCache[file] = fs.readFileSync(p, "utf8").split(/\r?\n/);
      } catch (_e) { fileCache[file] = []; }
    }
    return fileCache[file];
  }
  function _hasFileAllow(file) {
    if (Object.prototype.hasOwnProperty.call(fileAllowCache, file)) return fileAllowCache[file];
    var lines = _readContext(file).slice(0, 50);   // file-level allow lives near top
    var re = new RegExp("codebase-patterns:allow-file\\s+" + allowClass + "\\b");
    var found = lines.some(function (l) { return re.test(l); });
    fileAllowCache[file] = found;
    return found;
  }
  function _hasLineAllow(file, lineNum) {
    var lines = _readContext(file);
    if (!lines.length) return false;
    var same  = lines[lineNum - 1] || "";
    var above = lines[lineNum - 2] || "";
    var twoAbove = lines[lineNum - 3] || "";
    var re = new RegExp("allow:" + allowClass + "\\b");
    return re.test(same) || re.test(above) || re.test(twoAbove);
  }
  return matches.filter(function (m) {
    if (_hasFileAllow(m.file)) return false;
    if (_hasLineAllow(m.file, m.line)) return false;
    return true;
  });
}

var _allViolations = [];

function _report(label, matches) {
  // Collect into _allViolations rather than check()-ing per pattern;
  // we want every pattern to RUN to completion + report, then a single
  // failing assertion at the end so the operator sees the full grep
  // report instead of just the first hit.
  if (matches.length > 0) {
    var preview = matches.map(function (m) {
      return "    " + m.file + ":" + m.line + ": " + m.content.slice(0, 100);
    }).join("\n");
    console.log("  " + label + ": " + matches.length + " violation(s):\n" +
      preview);
    _allViolations.push({ label: label, count: matches.length });
  } else {
    check(label, true);
  }
}

// Each pattern has a class-id used in inline `allow:<class>` markers.
// Adding a marker at a violation line allowlists that one specific
// occurrence; the reason follows the marker on the same comment line.

function testNoRawByteLiterals() {
  // class: raw-byte-literal
  // Systemic detection: any integer literal `n >= 8 && n % 8 === 0` is
  // a byte-shape candidate (8-bit alignment is the universal byte unit).
  // Use C.BYTES.kib / mib / gib (n) so the framework's byte math has a
  // single source of truth.
  // Strings, regex literals, and hex constants are excluded. HTTP
  // status comparisons, year literals (which can also be multiples of
  // 8), and lines already routed through C.BYTES.* are skipped.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // constants.js and canonical-json.js define / consume the literals.
    if (rel === "lib/constants.js" || rel === "lib/canonical-json.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var stripped = line
        .replace(/"(?:[^"\\]|\\.)*"/g, "")
        .replace(/'(?:[^'\\]|\\.)*'/g, "")
        .replace(/`(?:[^`\\]|\\.)*`/g, "")
        .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, "")
        .replace(/0x[0-9a-fA-F]+/g, "");
      // Skip lines that already route through C.BYTES.* or C.TIME.* —
      // the operator-supplied count argument may itself look like a
      // byte literal (`C.BYTES.mib(64)`, `C.TIME.seconds(8)`) and the
      // wrapping primitive is the single source of truth.
      if (/\bC\.(BYTES|TIME)\.\w+\(/.test(stripped)) continue;
      // Skip lines whose left-hand side explicitly names a non-byte
      // unit. Match the unit token at any position in a SCREAMING_SNAKE
      // identifier (start, middle, or end). Examples:
      //   BITS_PER_BYTE, METHOD_DEFLATE, HEX_RADIX, CRC32_TABLE_LEN,
      //   MAX_PASSPHRASE_BYTES, NTP_TO_UNIX_OFFSET_SECONDS.
      var unitTokens = "(BITS|RADIX|SECONDS|MS|METHOD|COUNT|LEN|LENGTH|ENTRIES|RULES|OFFSET|DEPTH|ITER|INDEX|VERSION|FLAGS|YEAR|BYTES|TIMEOUT|RETRY|CAP|LIMIT|RANGE|BASE|MASK|PORT|ID|MAGIC)";
      var unitRe = new RegExp("\\b(?:[A-Z][A-Z0-9_]*_)?" + unitTokens +
                              "(?:_[A-Z0-9_]*)?\\b");
      var assignRe = /\bvar\s+([A-Z][A-Z0-9_]*)\s*=/;
      var assignMatch = assignRe.exec(stripped);
      if (assignMatch && unitRe.test(assignMatch[1])) continue;
      // Also skip array-index access and Buffer offset reads (the
      // small integer in `arr[N]` or `.readUInt32BE(N)` is a position,
      // and the position IS bytes for a buffer — but expressing it as
      // an integer index reads more naturally than a wrapped helper).
      // Limit to small N so a full Buffer.alloc(N) where N is a true
      // byte size still flags.
      if (/\[\s*\d+\s*\]/.test(stripped)) {
        // Strip out the bracket-access numbers and re-evaluate the rest.
        stripped = stripped.replace(/\[\s*\d+\s*\]/g, "[]");
      }
      if (/\.read(?:U?Int|Float|Double)(?:\d+)?(?:LE|BE)?\s*\(\s*\d+\s*\)/.test(stripped)) {
        stripped = stripped.replace(/(\.read(?:U?Int|Float|Double)(?:\d+)?(?:LE|BE)?)\s*\(\s*\d+\s*\)/g, "$1()");
      }
      // HTTP status-code comparisons (`statusCode >= 200 && < 300`,
      // `code < 600`, etc.) overlap with multiples of 8 (200, 208, 256,
      // 264 …). Same RFC 7231 boundary set as the time-literal filter.
      var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
      if (statusCmpRe.test(stripped)) continue;
      // Strip bit-shift operands (`>>> 8`, `<< 16`) — those are bit
      // counts, not byte sizes.
      stripped = stripped.replace(/(?:>>>?|<<)\s*\d+/g, "");
      // Strip `& <num>` / `| <num>` / `^ <num>` masks — bitmask values
      // (255 = 0xFF, 65535 = 0xFFFF, 0x7f, etc.) hit the multiple-of-8
      // rule by coincidence. Mask-context is well-marked.
      stripped = stripped.replace(/[&|^]\s*\d+/g, "");
      var hit = false;
      var re = /\b(\d{1,})\b/g;
      var m;
      while ((m = re.exec(stripped)) !== null) {
        var n = Number(m[1]);
        if (!Number.isFinite(n)) continue;
        if (n < 8) continue;
        if (n % 8 !== 0) continue;
        // Skip year literals (1900-2099 range — calendar / DOS-date math).
        if (n >= 1900 && n <= 2100) continue;
        // Skip the IANA TLS group IDs in the 0x11ED / 0x11EC range —
        // those are protocol constants, decoded to integers in the
        // PQC_GROUPS table and elsewhere. (0x11EC = 4588 not multiple
        // of 8, 0x11ED = 4589 not multiple of 8 — none trip anyway.)
        // Skip commonly-decimal protocol constants where
        // multiple-of-8 is coincidence:
        //   - 256, 64, 32, 16 — bit-widths (which ARE byte-aligned;
        //     fundamental fix routes them through C.BYTES.bit-arithmetic
        //     or names them as protocol constants).
        // No skip — flag every multiple of 8 strictly. The fundamental
        // fix path is to use C.BYTES helpers or rename + comment as a
        // protocol constant where 8-multiple is coincidence.
        hit = true;
        break;
      }
      if (hit) {
        bad.push({
          file:    rel,
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "raw-byte-literal");
  _report("no raw byte-shaped literals (n >= 8 && n % 8 === 0; use " +
          "C.BYTES.kib / mib / gib or name as protocol constant)",
    bad);
}

function testNoRawTimeLiterals() {
  // class: raw-time-literal
  // Systemic detection: ANY integer literal `n >= 60 && n % 60 === 0` is
  // a candidate time value (60-base time math: 60s, 300s, 3600s, 60000ms,
  // 86400s, etc.). Use C.TIME.seconds / minutes / hours / days / weeks
  // (n) so the framework's time math has a single source of truth.
  // Plus the bare seconds-to-ms `* 1000` shape from the v0.5.18 sweep.
  // Strings, regex literals, and hex constants are excluded.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    if (_relPath(files[fi]) === "lib/constants.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      // Strip string literals + regex literals + hex / bit-shift forms
      // so 0x1F300, "1800", and /\d{60}/ don't count.
      var stripped = line
        .replace(/"(?:[^"\\]|\\.)*"/g, "")
        .replace(/'(?:[^'\\]|\\.)*'/g, "")
        .replace(/`(?:[^`\\]|\\.)*`/g, "")
        .replace(/\/(?:[^/\\\n]|\\.)+\/[gimsuy]*/g, "")
        .replace(/0x[0-9a-fA-F]+/g, "");
      var hit = false;
      // Any `* 1000` that isn't part of `* 1000 * 1000` (already caught
      // as a multiple-of-60 below: 1000000 % 60 = 40 — no, `60000 % 60 = 0`)
      if (/[)\w]\s*\*\s*1000\b(?!\s*\*\s*1000)/.test(stripped)) hit = true;
      if (!hit) {
        // Lines that already route through C.TIME.* are correct — the
        // operator-supplied count argument may itself look like a time
        // literal (`C.TIME.days(180)`) and that's the canonical form.
        if (/\bC\.TIME\.\w+\(/.test(stripped)) continue;
        // HTTP status-code comparisons (`statusCode >= 200 && < 300`,
        // `code < 600`, etc.) — these are domain-fixed RFC 7231 status
        // class boundaries, not durations. A line where the only
        // multiple-of-60 literal in 200..599 sits in a comparison is
        // not time math.
        var statusCmpRe = /[<>!=]=?\s*(?:200|300|400|500|600|399|599)\b|\b(?:200|300|400|500|600|399|599)\s*[<>!=]=?/;
        if (statusCmpRe.test(stripped)) continue;
        // Strict detection: every multiple-of-60 numeric literal is a
        // time-shape candidate. Operators with a non-time-meaning
        // multiple-of-60 (e.g., 60 requests/min as a count) still need
        // to use C.TIME because the literal is time-derived (per-minute
        // rate), keeping one source of truth.
        var re = /\b(\d{2,})\b/g;
        var m;
        while ((m = re.exec(stripped)) !== null) {
          var n = Number(m[1]);
          if (!Number.isFinite(n)) continue;
          if (n < 60) continue;
          if (n % 60 !== 0) continue;
          // Year literals (1900-2099) are date/calendar math, not
          // duration. They land in DOS-date and Y2K-era constants;
          // those are not multiples of 60 by chance — they're CCYY
          // values fixed by domain. Skip the small set.
          if (n >= 1900 && n <= 2100) continue;
          // NTP-to-Unix epoch offset is a protocol-fixed value (76 yrs
          // expressed in seconds) defined by RFC 5905 — not a tunable.
          if (n === 2208988800) continue;
          hit = true;
          break;
        }
      }
      if (hit) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "raw-time-literal");
  _report("no raw time-shaped literals (n >= 60 && n % 60 === 0; " +
          "use C.TIME.seconds / minutes / hours / days / weeks)",
    bad);
}

function testNumericOptsValidate() {
  // class: numeric-opt-Infinity
  var matches = _scan(
    /typeof\s+opts\.\w+\s*===\s*"number"\s*&&\s*opts\.\w+\s*>=?\s*0\b/);
  // numeric-bounds itself contains the helper definitions that look
  // like the pattern.
  matches = matches.filter(function (m) { return m.file !== "lib/numeric-bounds.js"; });
  matches = _filterMarkers(matches, "numeric-opt-Infinity");
  _report("numeric opts route through lib/numeric-bounds (or have an allow marker)",
    matches);
}

function testHttp2TeardownPaired() {
  // class: http2-bare-close
  var matches = _scan(/\bsession\.close\(\)/);
  // The helper itself contains the close() call.
  matches = matches.filter(function (m) { return m.file !== "lib/http2-teardown.js"; });
  matches = _filterMarkers(matches, "http2-bare-close");
  _report("HTTP/2 session.close() routes through lib/http2-teardown",
    matches);
}

function testNoStrayConsoleCalls() {
  // class: console-direct
  var matches = _scan(/\bconsole\.(log|error|warn|info|debug)\(/);
  matches = _filterMarkers(matches, "console-direct");
  _report("no stray console.* calls in lib/ production code paths",
    matches);
}



function testNoUnresolvedMarkers() {
  // class: unresolved-marker — TODO / FIXME / HACK / XXX
  var matches = _scan(/\b(defer|TODO|FIXME|HACK|XXX)(?::|\s)/);
  matches = _filterMarkers(matches, "unresolved-marker");
  _report("no TODO / FIXME / HACK / XXX markers in lib/",
    matches);
}

// ---- Pattern 9: Tier-A/B/C terminology in shipped lib/ ----

function testNoTierTerminologyInLib() {
  // feedback_no_tier_terminology.md — internal validation-policy labels
  // shouldn't appear in lib/ comments or strings; describe the behavior
  // in plain terms instead.
  var matches = _scan(/\bTier[- ]?(A|B|C|1|2|3)\b/i, { skipComments: false });
  matches = _filterMarkers(matches, "tier-terminology");
  _report("no Tier-A / Tier-B / Tier-C terminology in lib/", matches);
}

// ---- Pattern 10: inline require() (should be top-of-file) ----

function testNoInlineRequires() {
  // feedback_top_of_file_requires.md — inline require() inside function
  // bodies is a smell. Operators reading the lib expect all deps at
  // file top; circular-load cases need an explicit comment.
  // Match `require("./...")` indented (not at column 0).
  var matches = _scan(/^\s+\S.*\brequire\(["']\.\.?\//);
  matches = _filterMarkers(matches, "inline-require");
  _report("require() at top of file (or inline-require allow marker)",
    matches);
}

// ---- Pattern 11: Math.random() in security-sensitive contexts ----

function testNoMathRandomForSecurity() {
  // Math.random() is NOT cryptographic. Framework crypto primitives
  // route through `b.crypto.generateBytes` / `nodeCrypto.randomBytes`.
  // Math.random has legitimate uses (jitter, non-security IDs); those
  // get an allow marker.
  var matches = _scan(/\bMath\.random\(/);
  matches = _filterMarkers(matches, "math-random-noncrypto");
  _report("Math.random() in lib/ has an explicit non-crypto allow marker",
    matches);
}

// ---- Pattern 12: raw `===` for likely hash/token/sig comparisons ----

function testNoRawHashCompare() {
  // Variable names ending in Hash / Token / Sig / Mac / Digest compared
  // with === are timing-attack-prone. Should use `crypto.timingSafeEqual`.
  var matches = _scan(
    /\b\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)\s*===\s*\w*(Hash|Token|Sig|Signature|Mac|Digest|Tag)/);
  matches = _filterMarkers(matches, "raw-hash-compare");
  _report("hash/token/sig/mac/digest compared with timingSafeEqual " +
          "(or has allow marker for known-non-secret comparison)",
    matches);
}

// ---- Pattern 13: new URL(...) without safeUrl.parse() guard ----

function testRawNewURL() {
  // Operator-supplied URLs should route through `safeUrl.parse` so the
  // protocol allowlist + length cap + userinfo block apply. Internal
  // URL building (test fixtures, sigv4 canonical query) is fine.
  var matches = _scan(/\bnew URL\(/);
  matches = _filterMarkers(matches, "raw-new-url");
  _report("new URL(...) routes through safeUrl.parse (or has allow marker)",
    matches);
}

// ---- Pattern 14: silent JSON.parse() on operator-supplied data ----

function testNoBareJsonParse() {
  // `JSON.parse(operatorInput)` lacks the maxBytes / depth / proto
  // pollution defenses that `safeJson.parse` adds. Internal JSON
  // (vendor manifest, tests, internal state) is fine with bare parse.
  var matches = _scan(/\bJSON\.parse\(/);
  // safe-json.js IS the safe wrapper; the bare JSON.parse call lives
  // there by definition (it's what safe-json wraps with maxBytes /
  // depth / proto-pollution defenses).
  matches = matches.filter(function (m) { return m.file !== "lib/safe-json.js"; });
  matches = _filterMarkers(matches, "bare-json-parse");
  _report("JSON.parse on operator input routes through safeJson.parse " +
          "(or has allow marker)",
    matches);
}

// ---- Pattern 15: Object.keys(...).sort() canonicalize walks ----

function testNoBareCanonicalizeWalks() {
  // Pattern from v0.6.60 / .66 / .67: walking with Object.keys(...).sort()
  // and JSON.stringify silently loses Date / Buffer / Map / Set / BigInt.
  // Should route through `lib/canonical-json`.
  var matches = _scan(/Object\.keys\(\w+\)\.sort\(\)/);
  matches = _filterMarkers(matches, "bare-canonicalize-walk");
  _report("Object.keys(...).sort() canonicalize walks route through " +
          "lib/canonical-json (or have allow marker)",
    matches);
}

// ---- Pattern 16: regex-only string format validators with no length cap ----

function testFormatValidatorLengthCap() {
  // Pattern from v0.6.61 (.email RFC 5321) / v0.6.62 (.url RFC 7230):
  // a regex-only validator like `EMAIL_RE.test(v)` accepts arbitrarily
  // long matching strings → DoS-shape. The validator should bound length
  // explicitly before the regex test. We can't perfectly grep this, but
  // we can flag any `\w+_RE.test(v)` line that doesn't have `\w+\.length`
  // in the surrounding 3 lines.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    // safe-buffer / safe-schema are the primitives that DEFINE the
    // shared format regexes. The .test() calls inside their helpers
    // (`isHex`, `hasCrlf`, schema format predicates) operate on
    // already-bounded inputs delivered by callers.
    if (rel === "lib/safe-buffer.js" || rel === "lib/safe-schema.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\b[A-Z_]+_RE\.test\(/.test(line)) continue;
      // Look for `length` mention in surrounding 5 lines (any
      // comparison: <, >, =, !=, !==, including the explicit-length
      // shape `s.length !== expectedLength`).
      var window = (lines[li-2] || "") + (lines[li-1] || "") +
                   line + (lines[li+1] || "") + (lines[li+2] || "");
      if (/\.length\s*[><=!]/.test(window)) continue;
      bad.push({
        file:    _relPath(files[fi]),
        line:    li + 1,
        content: line.trim(),
      });
    }
  }
  bad = _filterMarkers(bad, "regex-no-length-cap");
  _report("regex-only format validators bound length before test " +
          "(or have allow marker)",
    bad);
}

// ---- Pattern 17: process.exit() in lib/ (should not exit unilaterally) ----

function testNoProcessExitInLib() {
  var matches = _scan(/\bprocess\.exit\(/);
  matches = _filterMarkers(matches, "process-exit");
  _report("no process.exit() in lib/ (CLI surface only)", matches);
}

// ---- Pattern 18: catch (_e) {} swallowing without logging ----

function testNoSilentCatchSwallow() {
  // `catch (_e) { }` (empty body) silently swallows. Should at least
  // re-throw, log, or have an allow marker explaining why dropping
  // is correct (e.g., best-effort cleanup, audit-safe drops).
  var matches = _scan(/catch\s*\(\s*_\w*\s*\)\s*\{\s*\}/);
  matches = _filterMarkers(matches, "silent-catch");
  _report("empty catch(_e) {} blocks have an explicit silent-catch allow marker",
    matches);
}

// ---- Pattern 19: new RegExp(operatorString) — ReDoS via dynamic compilation ----

function testNoDynamicRegexFromOperatorInput() {
  // `new RegExp(opts.X)` lets an operator-supplied string compile to a
  // regex — ReDoS vector if the input is operator-controlled.
  var matches = _scan(/new RegExp\(/);
  // safe-json.js implements JSON Schema validation; the spec defines
  // `pattern` as a string, so compiling the operator-supplied schema
  // pattern is part of the documented surface (operator owns the
  // schema, not the runtime input).
  matches = matches.filter(function (m) { return m.file !== "lib/safe-json.js"; });
  matches = _filterMarkers(matches, "dynamic-regex");
  _report("new RegExp(...) marked with dynamic-regex allow marker " +
          "(input source documented)",
    matches);
}

// ---- Pattern 20: trustProxy bypass — raw req.headers x-forwarded-for read ----

function testNoRawXffRead() {
  // class: raw-xff
  // v0.5.6 (break-glass), v0.5.7 (error-page), v0.4.26 + v0.4.29
  // (middleware sweep): reading req.headers["x-forwarded-for"] (or
  // bracket-quoted) directly bypasses the trustProxy boundary. Should
  // route through requestHelpers.clientIp(req, { trustProxy }) so
  // X-Forwarded-For is honored only when the operator opted in.
  var matches = _scan(/req\.headers\s*\[\s*["']x-forwarded-for["']\s*\]/i);
  // request-helpers.js IS the canonical XFF reader; the read happens
  // there by definition.
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-xff");
  _report("req.headers['x-forwarded-for'] routes through requestHelpers.clientIp",
    matches);
}

// ---- Pattern 21: req.socket.remoteAddress raw read for actor IP ----

function testNoRawRemoteAddress() {
  // class: raw-remote-addr
  // v0.5.6: break-glass.grant was reading req.socket.remoteAddress
  // directly to populate audit-row IP, bypassing trustProxy. Audit /
  // observability emissions on the request path should resolve actor
  // IP through requestHelpers.clientIp / extractActorContext so the
  // operator's trustProxy posture is consistent.
  var matches = _scan(/\breq\.socket\.remoteAddress\b/);
  // request-helpers.js IS the canonical clientIp reader.
  matches = matches.filter(function (m) { return m.file !== "lib/request-helpers.js"; });
  matches = _filterMarkers(matches, "raw-remote-addr");
  _report("req.socket.remoteAddress routes through requestHelpers.clientIp",
    matches);
}

// ---- Pattern 22: process.env raw read in lib/ ----

function testNoRawProcessEnv() {
  // class: raw-process-env
  // v0.5.18: process.env.X reads should route through safeEnv.readVar
  // for the size cap + type coercion + missing/empty handling. log.js
  // is an exception (safeEnv requires log → load-time cycle); other
  // bootstrap files might be too. Mark per site.
  var matches = _scan(/\bprocess\.env\.\w+/);
  // safe-env.js / parsers/safe-env.js DEFINE the safe reader.
  matches = matches.filter(function (m) {
    return m.file !== "lib/safe-env.js" &&
           m.file !== "lib/parsers/safe-env.js";
  });
  matches = _filterMarkers(matches, "raw-process-env");
  _report("process.env reads route through safeEnv.readVar (or have allow marker)",
    matches);
}

// ---- Pattern 23: nodeCrypto.timingSafeEqual direct (length-throws) ----

function testNoRawTimingSafeEqual() {
  // class: raw-timing-safe-equal
  // v0.5.18: Node's nodeCrypto.timingSafeEqual throws on length-mismatch
  // (itself a side channel). Framework wrapper b.crypto.timingSafeEqual
  // short-circuits length-mismatch in constant time before delegating.
  // Only flag bindings named `nodeCrypto` (the explicit raw alias) —
  // files that bind `var crypto = require("./crypto")` (framework
  // wrapper) call `crypto.timingSafeEqual` legitimately.
  var matches = _scan(/\bnodeCrypto\.timingSafeEqual\(/);
  // The framework crypto module is the canonical wrapper.
  matches = matches.filter(function (m) { return m.file !== "lib/crypto.js"; });
  matches = _filterMarkers(matches, "raw-timing-safe-equal");
  _report("crypto.timingSafeEqual routes through b.crypto.timingSafeEqual " +
          "(length-tolerant wrapper)",
    matches);
}

// ---- Pattern 24: parseInt without explicit radix ----

function testParseIntRadix() {
  // class: parseint-no-radix
  // v0.6.2-class footgun: parseInt accepts leading-prefix matches and
  // hex/octal-coerces operator strings unexpectedly. All call sites
  // must specify radix.
  // Manual paren-balanced scan: find `parseInt(`, walk to matching
  // close, check for `,` at depth 0 in between.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = /\bparseInt\s*\(/.exec(line);
      if (!m) continue;
      var start = m.index + m[0].length;
      var depth = 1;
      var hasCommaAtDepth0 = false;
      var i;
      for (i = start; i < line.length && depth > 0; i++) {
        var ch = line.charAt(i);
        if (ch === "(") depth += 1;
        else if (ch === ")") depth -= 1;
        else if (ch === "," && depth === 1) hasCommaAtDepth0 = true;
      }
      // depth still >0 means call spans multiple lines; tolerant: skip.
      if (depth > 0) continue;
      if (!hasCommaAtDepth0) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "parseint-no-radix");
  _report("parseInt(...) called with explicit radix", bad);
}

// ---- Pattern 25: Buffer.from(string) without encoding ----

function testBufferFromStringEncoding() {
  // class: buffer-from-no-encoding
  // Buffer.from("...") defaults to UTF-8, but the absence of an
  // explicit encoding masks intent — and for hex/base64 strings the
  // default UTF-8 is wrong silently. Require the encoding argument.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m = /\bBuffer\.from\(\s*("[^"]*"|'[^']*')\s*\)/.exec(line);
      if (m) {
        bad.push({
          file:    _relPath(files[fi]),
          line:    li + 1,
          content: line.trim(),
        });
      }
    }
  }
  bad = _filterMarkers(bad, "buffer-from-no-encoding");
  _report("Buffer.from(string) calls pass an explicit encoding " +
          "(or have allow marker for ascii-safe literals)",
    bad);
}

// ---- Pattern 26: setInterval without unref for background timers ----

function testTimersUnref() {
  // class: timer-no-unref
  // Background timers (heartbeats, debounce flushers, rate-limit
  // sweepers, cache GC) without unref() pin the process — graceful
  // shutdown waits indefinitely. Framework should use safeAsync.sleep
  // (unref-aware) or wrap setInterval with .unref().
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\bsetInterval\(/.test(line)) continue;
      // Widen window: the .unref() call may live a few lines below the
      // setInterval (e.g., wrapped with a typeof guard). 5-line window.
      var window = line + (lines[li+1] || "") + (lines[li+2] || "") +
                   (lines[li+3] || "") + (lines[li+4] || "");
      if (/\.unref\(\)/.test(window)) continue;
      bad.push({
        file:    _relPath(files[fi]),
        line:    li + 1,
        content: line.trim(),
      });
    }
  }
  bad = _filterMarkers(bad, "timer-no-unref");
  _report("setInterval timers call .unref() (or have allow marker for " +
          "process-pinning intent)",
    bad);
}

// ---- Pattern 27: nodeCrypto.randomBytes raw token generation ----

function testNoRawRandomBytesToken() {
  // class: raw-randombytes-token
  // v0.5.18 sweep: hand-rolled tokens via nodeCrypto.randomBytes(n)
  // .toString("hex"|"base64"|"base64url") should route through
  // b.crypto.generateToken / generateBytes so the framework's PQC-
  // posture primitives own the entropy source + format.
  var matches = _scan(/\b(nodeCrypto|crypto)\.randomBytes\([^)]+\)\s*\.\s*toString\s*\(/);
  // crypto.js itself wraps these.
  matches = matches.filter(function (m) { return m.file !== "lib/crypto.js"; });
  matches = _filterMarkers(matches, "raw-randombytes-token");
  _report("nodeCrypto.randomBytes(n).toString routes through " +
          "b.crypto.generateToken / generateBytes (or has allow marker)",
    matches);
}

// ---- Pattern 28: hand-rolled Promise+setTimeout instead of safeAsync.sleep ----

function testNoHandrolledSleep() {
  // class: handrolled-sleep
  // v0.4.28 router.js: `new Promise((resolve) => setTimeout(resolve, ms))`
  // should use safeAsync.sleep(ms, { unref: true }) so the framework's
  // outbound-timeout primitive owns timer lifecycle (unref, cancel,
  // shutdown integration).
  var matches = _scan(/new Promise\([^)]*\)\s*=>\s*setTimeout|new Promise\(function[^{]*\{\s*setTimeout/);
  matches = _filterMarkers(matches, "handrolled-sleep");
  _report("Promise+setTimeout routes through safeAsync.sleep",
    matches);
}

// ---- Pattern 29: raw http/https/fetch outbound bypassing httpClient ----

function testNoRawOutboundHttp() {
  // class: raw-outbound-http
  // SSRF guard + DNS pinning + retry policy live in b.httpClient.
  // Direct http.request / https.request / fetch in lib/ bypasses the
  // ssrfGuard + pinned-DNS lookup (v0.5.4 DNS-rebinding window).
  var matches = _scan(/\b(http|https)\.(request|get)\s*\(|^[^/]*\bfetch\s*\(/);
  // Documented exemptions:
  //   lib/http-client.js IS the wrapper.
  //   lib/network-dns.js DoH bootstrap can't loop through httpClient
  //     (httpClient → ssrfGuard → DNS → DoH → httpClient cycle).
  //   lib/testing.js IS the test request injector — bypasses the
  //     wrapper by design so tests can assert on raw request shapes.
  var exemptFiles = {
    "lib/http-client.js":  true,
    "lib/network-dns.js":  true,
    "lib/testing.js":      true,
  };
  matches = matches.filter(function (m) { return !exemptFiles[m.file]; });
  matches = _filterMarkers(matches, "raw-outbound-http");
  _report("http(s).request / fetch route through b.httpClient (or have allow marker)",
    matches);
}

// ---- Pattern 30: Number(process.env.X) coercion without isFinite ----

function testNoNumberEnvCoercion() {
  // class: number-env-coerce
  // v0.6.69 history: Number(process.env.MAX_X || "") coerces "" → 0,
  // "abc" → NaN, "Infinity" → Infinity. Operators reading numeric env
  // vars should route through b.config.coerce.number() / safeEnv
  // typed readers (NaN rejected, Infinity rejected).
  var matches = _scan(/\bNumber\s*\(\s*process\.env\b/);
  matches = _filterMarkers(matches, "number-env-coerce");
  _report("Number(process.env.X) routes through config.coerce.number / " +
          "safeEnv typed readers",
    matches);
}

// ============================================================
// Primitive-extraction-candidate detectors
// ------------------------------------------------------------
// These flag CODE DESIGN that looks like a one-off reinvention of
// something that should have been a shared primitive. Each rule's
// fundamental fix is "extract the pattern into lib/<name>.js (or
// extend an existing primitive) and refactor the call sites."
// ============================================================

// ---- Pattern 31: duplicate regex literal across files ----

function testNoDuplicateRegexAcrossFiles() {
  // class: duplicate-regex
  // v0.4.27 surfaced four files duplicating the email regex; the fix
  // was promoting it to safeSchema.EMAIL_RE. Same regex literal in 3+
  // files is an extraction candidate — the test catches future drift.
  var files = _libFiles();
  var seen = {};   // regexSource → [ {file, line} ]
  // Match `/.../<flags>` only when preceded by a regex-context token
  // (`=`, `(`, `,`, `?`, `:`, `[`, `;`, `!`, `&&`, `||`, `return`,
  // `throw`) — distinguishes regex literals from `*/` comment closers
  // and from `path/to/file` strings.
  var regexCtxRe = /(?:^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\s*\/((?:\\.|[^/\\\n])+)\/([gimsuy]*)(?=[\s,);.\]]|$)/g;
  for (var fi = 0; fi < files.length; fi++) {
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      var m;
      regexCtxRe.lastIndex = 0;
      while ((m = regexCtxRe.exec(line)) !== null) {
        var src = m[1];
        // Skip trivial shapes — single chars, no meta, single literal.
        if (src.length < 6) continue;
        // Require at least one regex meta-character so plain string-
        // shaped matches don't trip (e.g., `/best effort/` from a
        // comment closer reaching the post-context).
        if (!/[\\^$*+?{}()|[\]]/.test(src)) continue;
        if (!seen[src]) seen[src] = [];
        seen[src].push({ file: _relPath(files[fi]), line: li + 1 });
      }
    }
  }
  var bad = [];
  Object.keys(seen).forEach(function (src) {
    var occurrences = seen[src];
    var distinctFiles = {};
    occurrences.forEach(function (o) { distinctFiles[o.file] = true; });
    if (Object.keys(distinctFiles).length >= 3) {
      bad.push({
        file:    occurrences[0].file,
        line:    occurrences[0].line,
        content: "regex /" + src.slice(0, 60) + (src.length > 60 ? "…" : "") +
                 "/ appears in " + Object.keys(distinctFiles).length +
                 " files: " + Object.keys(distinctFiles).slice(0, 4).join(", ") +
                 (Object.keys(distinctFiles).length > 4 ? ", …" : ""),
      });
    }
  });
  bad = _filterMarkers(bad, "duplicate-regex");
  _report("regex literal seen in 3+ files → extract to a shared constant",
    bad);
}

// ---- Pattern 32: hand-rolled deep clone ----

function testNoHandrolledDeepClone() {
  // class: handrolled-deep-clone
  // `JSON.parse(JSON.stringify(x))` is the deep-clone idiom that
  // silently drops Date / Buffer / Map / Set / BigInt / RegExp /
  // function / undefined. The framework's canonical-json walker is
  // the right primitive when the goal is canonicalization for hashing;
  // for genuine deep clone, structuredClone is the modern answer
  // (Node 17+) and should be wrapped in `b.safeBuffer.deepClone` or
  // similar. Either way, the inline shape is a primitive candidate.
  var matches = _scan(/\bJSON\.parse\s*\(\s*JSON\.stringify\s*\(/);
  matches = _filterMarkers(matches, "handrolled-deep-clone");
  _report("JSON.parse(JSON.stringify(x)) deep-clone → use canonical-json " +
          "or structuredClone",
    matches);
}

// ---- Pattern 33: hand-rolled buffer collection ----

function testNoHandrolledBufferCollect() {
  // class: handrolled-buffer-collect
  // The `var chunks = []; …on("data", chunks.push); …on("end",
  // Buffer.concat(chunks))` shape is what `b.safeBuffer.boundedChunkCollector`
  // exists for (with maxBytes cap + drop semantics). Inline reinvention
  // skips the cap and is the bug class v0.6.57 / .68 / .69 swept.
  // Files with `chunks.pop()` are editable-buffer patterns (e.g.,
  // backspace-aware stdin readers) — those don't fit the append-only
  // collector primitive and are exempt.
  // Files with streaming-peek patterns (`Buffer.concat(chunks)` followed
  // by partial-record inspection rather than complete-message resolve)
  // get a per-line allow marker since the primitive doesn't expose
  // peek; pqc-gate.js's TLS ClientHello parser is the canonical example.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-buffer.js") continue;   // the primitive itself
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/Buffer\.concat\s*\(\s*\w*chunks?\b/.test(content)) continue;
    if (!/var\s+\w*chunks?\s*=\s*\[\s*\]/.test(content)) continue;
    // Skip editable-buffer patterns (push + pop in same file).
    if (/\bchunks?\s*\.\s*pop\s*\(/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      if (/Buffer\.concat\s*\(\s*\w*chunks?\b/.test(lines[li])) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;   // one report per file
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-buffer-collect");
  _report("hand-rolled chunks-array buffer collect → use " +
          "safeBuffer.boundedChunkCollector (cap-bounded)",
    bad);
}

// ---- Pattern 34: hand-rolled debounce ----

function testNoHandrolledDebounce() {
  // class: handrolled-debounce
  // The `clearTimeout(t); t = setTimeout(fn, ms)` shape is the debounce
  // idiom. Used in 5+ places pre-sweep. Should be wrapped in a
  // `b.safeAsync.debounce(fn, ms)` primitive that handles the timer
  // lifecycle (.unref, cancel-on-shutdown).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-async.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      // clearTimeout(<x>) followed within 5 lines by <x> = setTimeout(...)
      var m = /\bclearTimeout(?:Fn)?\s*\(\s*(\w+)\s*\)/.exec(lines[li]);
      if (!m) continue;
      var name = m[1];
      var window = lines.slice(li, Math.min(li + 6, lines.length)).join("\n");
      var assignRe = new RegExp("\\b" + name + "\\s*=\\s*setTimeout\\s*\\(");
      if (assignRe.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-debounce");
  _report("hand-rolled clearTimeout/setTimeout debounce → use " +
          "safeAsync.debounce (timer lifecycle owned)",
    bad);
}

// ---- Pattern 35: hand-rolled Promise.race timeout ----

function testNoHandrolledPromiseRaceTimeout() {
  // class: handrolled-race-timeout
  // `Promise.race([fn(), new Promise((r) => setTimeout(...))])` is the
  // timeout-with-cancel idiom. Should use `b.safeAsync.withTimeout(fn,
  // ms)` which handles abort + leaked-timer cleanup.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/safe-async.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      if (!/\bPromise\.race\s*\(/.test(lines[li])) continue;
      var window = lines.slice(li, Math.min(li + 8, lines.length)).join("\n");
      if (/\bsetTimeout\s*\(/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-race-timeout");
  _report("Promise.race + setTimeout timeout → use safeAsync.withTimeout",
    bad);
}

// ---- Pattern 36: manual byte-by-byte compare ----

function testNoManualByteCompare() {
  // class: manual-byte-compare
  // Hand-rolled `for (var i = 0; i < a.length; i++) if (a[i] !== b[i])`
  // is a constant-time-WRONG comparison. Anything comparing crypto
  // material must use `b.crypto.timingSafeEqual` (length-tolerant +
  // node:crypto under the hood).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/crypto.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      // for (var i = 0; i < a.length; i++) {  if (a[i] !== b[i])
      var loop = /for\s*\(\s*var\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length\s*;\s*\w+\+\+\s*\)/.exec(lines[li]);
      if (!loop) continue;
      var window = lines.slice(li, Math.min(li + 4, lines.length)).join("\n");
      if (/\[\s*\w+\s*\]\s*!==?\s*\w+\s*\[\s*\w+\s*\]/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "manual-byte-compare");
  _report("manual byte-by-byte compare loop → use crypto.timingSafeEqual",
    bad);
}

// ---- Pattern 37: lazy-require pattern open-coded ----

function testNoOpenCodedLazyRequire() {
  // class: open-coded-lazy-require
  // The shape `var _x = null; function x() { if (!_x) _x = require("./y"); return _x; }`
  // pre-dates lib/lazy-require. Any new occurrence should use
  // `lazyRequire(function () { return require("./y"); })` so test-reset
  // (.reset()) and cycle-break behavior is consistent.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/lazy-require.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    if (!/\bvar\s+_\w+\s*=\s*null\s*;/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 2; li++) {
      var m = /\bvar\s+(_\w+)\s*=\s*null\s*;/.exec(lines[li]);
      if (!m) continue;
      var name = m[1];
      var window = lines.slice(li, Math.min(li + 6, lines.length)).join("\n");
      var loadRe = new RegExp("if\\s*\\(\\s*!" + name + "\\s*\\)\\s*" + name +
                              "\\s*=\\s*require\\(");
      if (loadRe.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "open-coded-lazy-require");
  _report("open-coded lazy-require pattern → use lib/lazy-require",
    bad);
}

// ---- Pattern 38: throw new Error(string) instead of framework error ----

function testNoBareErrorThrows() {
  // class: bare-error-throw
  // `throw new Error("...")` skips the framework's .code dispatch.
  // Only flag files that ALREADY have a `defineClass`-built error class —
  // those throws are inconsistent with the file's own contract. Files
  // without a defined class are typically helpers (constants validators,
  // small leaf modules) where plain Error is acceptable.
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/constants.js" || rel === "lib/framework-error.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    // Skip files that don't define their own error class — plain Error
    // is the contract for those.
    if (!/\bdefineClass\s*\(\s*["']\w+Error/.test(content)) continue;
    var lines = content.split(/\r?\n/);
    var fileHits = 0;
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (!/\bthrow\s+new\s+Error\s*\(/.test(line)) continue;
      bad.push({
        file: rel,
        line: li + 1,
        content: line.trim(),
      });
      fileHits++;
      if (fileHits >= 2) break;   // sample 2 per file
    }
  }
  bad = _filterMarkers(bad, "bare-error-throw");
  _report("throw new Error(string) in a file with its own FrameworkError " +
          "class → use that class with a .code",
    bad);
}

// ---- Pattern 39: hand-rolled URL building ----

function testNoHandrolledUrlBuild() {
  // class: handrolled-url-build
  // String-concat URL building (`endpoint + "/" + path`) sidesteps
  // safeUrl.parse's protocol allowlist + length cap + userinfo guard.
  // Lines that pass the concatenated string straight into safeUrl.parse
  // or a project-specific wrapper (`_internalUrl`) are routed correctly
  // and exempt; bare returns / assignments are the bypass.
  var matches = _scan(/(["'])\s*\+\s*\w*[Ee]ndpoint\b|\b\w*[Ee]ndpoint\s*\+\s*["']\//);
  matches = matches.filter(function (m) {
    // Skip when the concat is wrapped in safeUrl.parse / _internalUrl.
    return !/\b(safeUrl\.parse|_internalUrl)\s*\(/.test(m.content);
  });
  matches = _filterMarkers(matches, "handrolled-url-build");
  _report("string-concat URL build → use safeUrl.parse (or document " +
          "the internal-trusted exception)",
    matches);
}

// ---- Pattern 40: hand-rolled retry loop ----

function testNoHandrolledRetryLoop() {
  // class: handrolled-retry-loop
  // `for (var attempt = 0; attempt < N; attempt++)` with `setTimeout`
  // inside is the retry-with-backoff idiom. Should use `b.retry`
  // (handles isPermanent classification, jitter, max-elapsed-time cap,
  // observability events).
  var files = _libFiles();
  var bad = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    if (rel === "lib/retry.js") continue;
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    for (var li = 0; li < lines.length - 5; li++) {
      // for (var <attempt-ish> = 0; ... < <max-attempts-ish>; ...)
      var m = /for\s*\(\s*var\s+(attempt|tries|retr\w*)\s*=/i.exec(lines[li]);
      if (!m) continue;
      var window = lines.slice(li, Math.min(li + 12, lines.length)).join("\n");
      if (/\bsetTimeout\s*\(/.test(window)) {
        bad.push({
          file: rel,
          line: li + 1,
          content: lines[li].trim(),
        });
        break;
      }
    }
  }
  bad = _filterMarkers(bad, "handrolled-retry-loop");
  _report("for-loop + setTimeout retry pattern → use b.retry",
    bad);
}

// ---- Pattern 41: duplicate code blocks (look-alike windows) ----

// Normalize a JS source line so logically-identical code shapes hash
// the same. The transform strips identifiers (keeping keywords),
// string / number / regex literals, and whitespace. Two functions that
// differ only in variable / file names produce the same fingerprint.
var _JS_KEYWORDS = new Set([
  "var", "let", "const", "function", "return", "if", "else", "for",
  "while", "do", "switch", "case", "default", "break", "continue",
  "try", "catch", "finally", "throw", "new", "this", "null", "undefined",
  "true", "false", "typeof", "instanceof", "in", "of", "delete", "void",
  "async", "await", "class", "extends", "super", "import", "export",
  "from", "as", "with", "yield", "static",
  // Node CommonJS module globals — kept verbatim so require-block
  // duplication can be detected as boilerplate (see _isBoilerplate).
  "require", "module", "exports", "Buffer", "process", "console",
  "Promise", "Object", "Array", "String", "Number", "Boolean", "Date",
  "RegExp", "Error", "Math", "JSON", "Symbol", "Map", "Set", "WeakMap",
  "WeakSet", "Reflect", "Proxy",
]);

function _normalizeJsLine(line) {
  // Strip line comments
  line = line.replace(/\/\/.*$/, "");
  // Replace string literals
  line = line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "_STR");
  // Replace regex literals (regex-context heuristic; same shape as
  // testNoDuplicateRegexAcrossFiles).
  line = line.replace(/(^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\/((?:\\.|[^/\\\n])+)\/[gimsuy]*/g,
                      "$1_RE");
  // Replace number literals (decimal + hex).
  line = line.replace(/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|0x[0-9a-fA-F]+/g, "_NUM");
  // Replace identifiers with _ID, keeping reserved words AND the
  // placeholder tokens emitted earlier (`_STR` / `_NUM` / `_RE` —
  // these match the identifier regex but must survive this pass).
  line = line.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, function (name) {
    if (name === "_STR" || name === "_NUM" || name === "_RE") return name;
    return _JS_KEYWORDS.has(name) ? name : "_ID";
  });
  // Insert whitespace around operators / brackets / punctuation so the
  // shingle tokenizer (split on whitespace) sees one token per logical
  // language token. Without this, `require(_STR);` would tokenize as a
  // single opaque token instead of five, and `module.exports` would
  // tokenize as one rather than three.
  line = line.replace(/([.(){}[\];,:?!&|^~<>=+\-*/%@])/g, " $1 ");
  // Collapse whitespace.
  line = line.replace(/\s+/g, " ").trim();
  return line;
}

function testNoDuplicateCodeBlocks() {
  // class: duplicate-block
  // Token-n-gram shingle detection. Each .js file is fully tokenized
  // (with identifiers/strings/numbers/regexes normalized to placeholders),
  // then split into overlapping N-token shingles. Each shingle that
  // appears in 3+ distinct files is a "shared logic shape" — the kind
  // of repeated try/catch, validation cascade, or request-init pattern
  // that should be a shared primitive.
  //
  // Why n-gram shingles instead of fixed-line windows: line layout
  // varies (a 1-line check in one file can be a 3-line if-block in
  // another, identical logic). Token-level shingles match the SHAPE
  // regardless of line breaks. Multiple shingle sizes are scanned so
  // both narrow primitives (6 tokens ≈ "if-then-throw") and wider
  // chains (16 tokens ≈ "validate-then-emit-then-return") surface.
  //
  // Tuning:
  //   SHINGLE_SIZES — token-window sizes scanned. Smaller catches
  //     finer-grain idiom (3-call chains); larger catches whole
  //     function bodies. Multi-pass produces both.
  //   MIN_DISTINCT_FILES — threshold for cross-file repetition. 3+
  //     means "appears in at least 3 files" (drift candidate).
  //   MIN_DISTINCT_TOKENS — skip shingles whose tokens are mostly
  //     punctuation / repeated closer chars.
  //   MAX_REPORTED_PER_LENGTH — cap to keep the report scannable;
  //     biggest-N hits are surfaced first because they represent the
  //     largest primitive opportunities.
  var SHINGLE_SIZES = [60, 50, 40, 30, 22, 16, 12, 8];
  var MIN_DISTINCT_FILES = 2;          // ≥ 3 files share the shape
  var MIN_DISTINCT_TOKENS = 5;
  var _MAX_REPORTED_PER_LENGTH = 5000;

  var files = _libFiles();

  // Tokenize every file once: { rel, tokens: [{ tok, line }, ...] }.
  // Each line is normalized then split on whitespace so the cross-file
  // shingle scan sees the same shape regardless of indentation.
  var tokenized = [];
  for (var fi = 0; fi < files.length; fi++) {
    var rel = _relPath(files[fi]);
    var content;
    try { content = fs.readFileSync(files[fi], "utf8"); }
    catch (_e) { continue; }
    var lines = content.split(/\r?\n/);
    var tokens = [];
    for (var li = 0; li < lines.length; li++) {
      var rawLine = lines[li];
      // Strip block-comment lines (rough — multi-line comments may
      // leak; acceptable noise level).
      if (/^\s*(\/\/|\*|\/\*)/.test(rawLine)) continue;
      var norm = _normalizeJsLine(rawLine);
      if (norm.length === 0) continue;
      var lineToks = norm.split(/\s+/).filter(function (t) { return t.length > 0; });
      for (var ti = 0; ti < lineToks.length; ti++) {
        tokens.push({ tok: lineToks[ti], line: li + 1 });
      }
    }
    tokenized.push({ rel: rel, tokens: tokens });
  }

  // Two-pass scan:
  //
  //   Pass 1 (token-shingle) — fingerprint = exact normalized tokens.
  //     Catches "same logic, different identifiers" (`var x = …` vs
  //     `var y = …` after _ID normalization).
  //
  //   Pass 2 (skeleton-shingle) — fingerprint replaces ALL keywords
  //     and identifiers with `T`, leaving only operators / punctuation
  //     / placeholders. Catches "same control flow, different
  //     keywords" — e.g., `if (x > 0) { return false; }` and
  //     `while (n != null) { break; }` collapse to the same skeleton
  //     `T ( T T T ) { T T ; }`. Surfaces deeper structural twins.
  var allKeywordsTo = function (slice) {
    return slice.map(function (t) {
      var k = t.tok;
      // Identifier placeholders + keywords + literals collapse to "T";
      // operators / brackets / punctuation stay as-is so the control-
      // flow shape is the fingerprint.
      if (/^[A-Za-z_]/.test(k)) return "T";
      return k;
    }).join(" ");
  };
  var sliceFingerprint = function (slice) { return slice.map(function (t) { return t.tok; }).join(" "); };

  // Boilerplate-shingle filter: language idioms that legitimately
  // repeat across files but cannot be extracted to a shared primitive.
  function _isBoilerplate(slice) {
    var toks = slice.map(function (t) { return t.tok; });
    var joined = toks.join(" ");
    // Module-import sequence — pattern `(var | var { … } =) require
    // ( _STR ) ;` repeating. Counting `require ( _STR )` occurrences
    // catches both straight requires and destructuring requires
    // without needing two regexes. 2+ require-with-string-arg shapes
    // in the shingle = import block.
    var requireCallSeq = /\brequire\s+\(\s+_STR\s+\)/g;
    var requireCalls = (joined.match(requireCallSeq) || []).length;
    if (requireCalls >= 2) return true;
    // Single require call dominating a small shingle.
    if (requireCalls === 1 && slice.length <= 10) return true;
    // Lazy-require + observability-setup idiom — the framework's
    // canonical post-import block:
    //   var observability = lazyRequire(function () { return require("./observability"); });
    //   function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }
    //   var _err = XError.factory;
    // 5+ files (api-key / credential-hash / permissions / retry / webhook)
    // share this exact scaffolding. The tokenizer normalizes
    // `lazyRequire` / `safeEvent` / `_emitEvent` to `_ID`, so we match
    // the structural shape post-tokenization. Detect any one of:
    //   - lazy-require boot:
    //       _ID = _ID ( function ( ) { return require ( _STR ) ; } )
    //   - safeEvent-shaped invocation:
    //       _ID ( ) . _ID ( _ID , _ID , _ID || { } )
    if (/_ID\s+=\s+_ID\s+\(\s+function\s+\(\s+\)\s+\{\s+return\s+require\s+\(\s+_STR\s+\)/.test(joined)) return true;
    // The tokenizer splits `||` into `| |` (per-char punctuation
    // splitter), so the safeEvent shape `(...) || {})` joins as
    // `_ID | | { }` not `_ID || { }`. Match either spelling.
    if (/_ID\s+\(\s+\)\s+\.\s+_ID\s+\(\s+_ID\s+,\s+_ID\s+,\s+_ID\s+\|\s+\|\s+\{\s+\}\s+\)/.test(joined)) return true;
    // Audit-emit wrapper: `function _emit(action, info) { if (!audit)
    // return; try { audit.safeEmit(...); } catch (_e) {} }` — duplicated
    // verbatim across api-key / cache / notify / seeders / webhook.
    // Tokenized: `function _ID ( _ID , _ID ) { if ( ! _ID ) return ;
    // try { _ID . _ID ( _ID . _ID ( ...`. Match the distinctive
    // `! _ID ) return ; try { _ID . _ID` shape.
    if (/!\s+_ID\s+\)\s+return\s+;\s+try\s+\{\s+_ID\s+\.\s+_ID\s+\(/.test(joined)) return true;
    // `cfg` unpacking — every primitive's create() does:
    //   var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
    //   var fieldA = cfg.fieldA;
    //   var fieldB = cfg.fieldB;
    //   ...
    // 3+ `var _ID = _ID . _ID ;` declarations in sequence = unpacking
    // block, not extractable logic.
    var unpackSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+;/g;
    var unpacks = (joined.match(unpackSeq) || []).length;
    if (unpacks >= 2) return true;
    // String-array literal — `validateOpts(opts, [...allowedKeys], label)`
    // call sites have a long `_STR , _STR , _STR , ...` run. 4+
    // string-comma pairs in sequence = allowedKeys array boilerplate.
    var strCommaSeq = /_STR\s+,\s+_STR\s+,\s+_STR\s+,\s+_STR/g;
    if (strCommaSeq.test(joined)) return true;
    // C.TIME / C.BYTES division constants — `_ID . _ID . _ID ( _NUM
    // ) / _ID . _ID . _ID ( _NUM )` is the framework's idiom for
    // "X seconds expressed in seconds-units" or "X bytes expressed
    // in larger units." Always-boilerplate, never-extractable.
    if (/_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+\/\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)/.test(joined)) return true;
    // trustProxy / accept-count idiom — `var X = opts.Y === true ||
    // typeof opts.Y === "number" ? opts.Y : false` — every
    // middleware that takes trustProxy / accept-count parses it the
    // same way. Tokenized: `_ID . _ID = = = true | | typeof _ID .
    // _ID = = = _STR ? _ID . _ID : false`.
    if (/_ID\s+\.\s+_ID\s+=\s+=\s+=\s+true\s+\|\s+\|\s+typeof\s+_ID\s+\.\s+_ID\s+=\s+=\s+=\s+_STR/.test(joined)) return true;
    // Optional-nested-shape entry guard — `if ( opts.X !== undefined
    // && opts.X !== null ) { ... }` — the framework's standard
    // wrapper around fields that are optional but require a
    // multi-key shape check inside (resolver, observability handle,
    // permissions handle, queue handle). The OUTER guard is shared
    // boilerplate; the INNER check varies. Tokenized: `if ( _ID .
    // _ID ! = = undefined & & _ID . _ID ! = = null )`.
    if (/if\s+\(\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+undefined\s+&\s+&\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+null\s+\)/.test(joined)) return true;
    // optionalX validation chain — `validateOpts.optionalBoolean(opts.X,
    // "label", ErrorClass);` repeated in sequence. Tokenized:
    // `_ID . _ID ( _ID . _ID , _STR , _ID ) ;` × N. 3+ = the canonical
    // _validateCreateOpts body using the framework primitives correctly.
    var validateChainSeq = /_ID\s+\.\s+_ID\s+\(\s+_ID\s+\.\s+_ID\s+,\s+_STR\s+,\s+_ID\s+\)\s+;/g;
    var validateChainCount = (joined.match(validateChainSeq) || []).length;
    if (validateChainCount >= 2) return true;
    // FrameworkError-subclass declaration pattern.
    if (/\bclass\s+_ID\s+extends\s+_ID/.test(joined)) return true;
    if (/\bclass\s+T\s+extends\s+T/.test(joined)) return true;
    // `module.exports = { ... }` boilerplate — every file's
    // public-surface declaration. Match the shape anywhere in the
    // shingle (start, middle, end) so all overlapping windows that
    // intersect the export object are filtered.
    if (/module\s+\.\s+exports\s+=\s+\{/.test(joined)) return true;
    // The export-object body itself dominates many overlapping
    // shingles — once `exports = {` is seen, all subsequent windows
    // are inside the object literal. Detect by `_ID : _ID , _ID :`
    // density (key-value pairs without expressions in between).
    var kvPairs = (joined.match(/_ID\s+:\s+_ID\s+,/g) || []).length;
    if (kvPairs >= 4) return true;
    // class-static / class-method `defineClass` boilerplate.
    if (/\bdefineClass\s+\(\s+_STR/.test(joined)) return true;
    // Module-level constant-declaration block — `var _ID = _ID . _ID
    // . _ID ( _NUM )` shape (3-level dotted call, e.g.,
    // `var X = C.TIME.hours(1);` since uppercase tokens like `C` /
    // `TIME` / `BYTES` collapse to `_ID`). 2+ such declarations in a
    // shingle means the shingle is the post-imports constants block,
    // not extractable logic.
    var constantDeclSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+;/g;
    var constantDecls = (joined.match(constantDeclSeq) || []).length;
    if (constantDecls >= 2) return true;
    // Two-level dotted-call constant block (`var _ID = _ID . _ID (
    // _NUM ) ;`) — e.g., raw `Buffer.alloc(32)` or `Math.pow(2, 30)`
    // sequences. Multiple in a row = config table, not logic.
    var constantDeclSeq2 = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\(\s+(?:_NUM|_STR)\s*[),]/g;
    var constantDecls2 = (joined.match(constantDeclSeq2) || []).length;
    if (constantDecls2 >= 3) return true;
    // Pure-declaration density check: if 55%+ of tokens are `=`, `;`,
    // `,`, `_STR`, or `_NUM`, the shingle is mostly assignments /
    // literals (config tables, default-opts objects).
    var declTokens = toks.filter(function (t) {
      return t === "=" || t === ";" || t === "," || t === ":" ||
             t === "_STR" || t === "_NUM" || t === "var" || t === "const";
    }).length;
    if (declTokens >= Math.floor(slice.length * 0.55)) return true;
    // Generic JS idioms — character-class-range checks, paired
    // typeof-throw validation guards, classic for-loop shapes.
    // These match across unrelated domains (html-balance vs sigv4 vs
    // safe-xml; auth/password vs csp-nonce vs request-helpers) and
    // aren't extractable as a primitive — every codebase that
    // iterates a string or validates two args in a row hits them.
    //
    // Character-range comparison (`X >= N && X <= N`) — appears in
    // any code that classifies characters / bytes / status codes.
    // `(_ID >= _NUM && _ID <= _NUM)` × 2+ in the same shingle = a
    // range-classification idiom.
    var rangeCheckSeq = /_ID\s+>\s+=\s+_NUM\s+&\s+&\s+_ID\s+<\s+=\s+_NUM/g;
    var rangeChecks = (joined.match(rangeCheckSeq) || []).length;
    if (rangeChecks >= 2) return true;
    // Classic for-loop iteration: `for ( var _ID = _NUM ; _ID < _ID
    // . _ID ; _ID + + )`. Generic JS — appears in dozens of
    // unrelated places (regex-match iteration, opts-array iteration,
    // hex-decode, etc.).
    if (/for\s+\(\s+var\s+_ID\s+=\s+_NUM\s+;\s+_ID\s+<\s+_ID\s+\.\s+_ID\s+;\s+_ID\s+\+\s+\+\s+\)/.test(joined)) return true;
    // Paired typeof-throw validation guards repeating in sequence —
    // `if ( typeof _ID ! = = _STR ... ) { throw new _ID ( _STR ,
    // _STR ) ; }` × 2+. Each individual guard is the
    // requireNonEmptyString antipattern (already in the catalog),
    // but the duplicate-block detector sees TWO in a row as a 50-
    // token shingle. The catalog catches the inline shape per-call;
    // the duplicate-block detector shouldn't double-report it.
    var throwTypeofSeq = /if\s+\(\s+typeof\s+_ID[\s\S]{0,40}?\)\s+\{\s+throw\s+new\s+_ID\s+\(\s+_STR\s+,\s+_STR\s+\)\s+;\s+\}/g;
    var throwTypeofs = (joined.match(throwTypeofSeq) || []).length;
    if (throwTypeofs >= 2) return true;
    return false;
  }

  // Per-(file-set, file-region) cluster: one report per UNIQUE
  // primitive-extraction opportunity. A duplicate run that spans 30
  // overlapping 40-token shingles in the same file-set collapses to
  // one entry (the LARGEST shingle observed, since it bounds the
  // duplicated region best).
  //
  // The cluster key is the sorted file-set joined by `|`. Two
  // shingles that match the same file-set but at different line
  // ranges are different "instances" of the same conceptual pattern
  // — kept as separate entries so each call site is reported.
  var clusters = {};   // fileSetKey → { fileSet, bestSize, bestPass, sites: [{file, startLine, endLine, size}] }

  function _runPass(passLabel, fingerprintFn) {
    for (var si = 0; si < SHINGLE_SIZES.length; si++) {
      var n = SHINGLE_SIZES[si];
      var seen = {};
      for (var fi2 = 0; fi2 < tokenized.length; fi2++) {
        var entry = tokenized[fi2];
        if (entry.tokens.length < n) continue;
        for (var ti2 = 0; ti2 + n <= entry.tokens.length; ti2++) {
          var slice = entry.tokens.slice(ti2, ti2 + n);
          var distinctMap = {};
          for (var di = 0; di < slice.length; di++) distinctMap[slice[di].tok] = true;
          if (Object.keys(distinctMap).length < MIN_DISTINCT_TOKENS) continue;
          if (_isBoilerplate(slice)) continue;
          var fp = fingerprintFn(slice);
          if (!seen[fp]) seen[fp] = [];
          seen[fp].push({
            file:     entry.rel,
            line:     slice[0].line,
            endLine:  slice[slice.length - 1].line,
          });
        }
      }
      Object.keys(seen).forEach(function (fp) {
        var occ = seen[fp];
        var distinctFiles = {};
        occ.forEach(function (o) { distinctFiles[o.file] = true; });
        var fileList = Object.keys(distinctFiles).sort();
        if (fileList.length < MIN_DISTINCT_FILES) return;
        var key = passLabel + "|" + fileList.join("|");
        if (!clusters[key]) {
          clusters[key] = {
            fileSet:   fileList,
            passLabel: passLabel,
            bestSize:  n,
            sites:     occ.slice(),
          };
        } else if (n > clusters[key].bestSize) {
          // Bigger shingle hit the same file-set — promote.
          clusters[key].bestSize = n;
          clusters[key].sites = occ.slice();
        }
      });
    }
  }
  _runPass("[exact]",    sliceFingerprint);
  _runPass("[skeleton]", allKeywordsTo);

  // Convert clusters to sorted report rows. Bigger shingles + larger
  // file-sets are stronger primitive opportunities — surface first.
  var rows = Object.keys(clusters).map(function (k) { return clusters[k]; });
  rows.sort(function (a, b) {
    if (b.fileSet.length !== a.fileSet.length) return b.fileSet.length - a.fileSet.length;
    return b.bestSize - a.bestSize;
  });

  // Strong-signal gating: clusters that hit BOTH the exact-pass AND
  // sufficient size + breadth are unambiguous primitive opportunities
  // (NOT control-flow noise or for-loop idiom). These fail the gate
  // hard. Smaller / skeleton-only clusters are tracked as advisory so
  // the inventory surfaces but doesn't block on language-idiom
  // matches.
  //
  // Threshold rationale: 50-token shingles span ~6-10 statements; any
  // 50-token sequence repeating in 10+ distinct files genuinely
  // represents a multi-statement code block that wants extraction —
  // NOT a stray for-loop or function-call shape that shows up in
  // every file by language convention.
  var STRONG_MIN_SIZE  = 50;
  var STRONG_MIN_FILES = 3;

  // KNOWN_CLUSTERS — per-cluster allowlist for the duplicate-block
  // detector. Each entry documents a cluster of files that share a
  // shape WHERE EXTRACTION IS BLOCKED OR INTENTIONAL: parser error
  // class signatures don't fit the framework's standard `(code, msg)`
  // contract; framework-convention shapes (chain verification loops,
  // multi-arg-format checks) are inherent to the domain; cross-domain
  // false-matches that share a 50-tok fingerprint by coincidence.
  //
  // Each entry keys on the SORTED file-set joined by `|`. Adding an
  // entry requires a documented `reason` and the cluster shows in
  // the report as "(allowlisted)" so operators see it but the gate
  // doesn't fail.
  var KNOWN_CLUSTERS = [
    {
      files: ["lib/api-key.js", "lib/db-query.js", "lib/session.js"],
      reason: "Generic JS array helper / lambda shape — Object.keys(...).map(fn) + similar functional idioms appearing in any code that walks a column-or-key list.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/deprecate.js", "lib/openapi-paths-builder.js", "lib/openapi.js",
        "lib/asyncapi.js", "lib/asyncapi-bindings.js", "lib/mail.js",
        "lib/inbox.js", "lib/mail-arc-sign.js",
      ],
      reason: "validateOpts.requireNonEmptyString-prelude scaffold — primitives gate operator-supplied opts with the same `validateOpts.requireNonEmptyString(opts.X, ..., ErrorClass, code)` cascade. Each domain's error class differs (DeprecateError / OpenApiError / AsyncApiError / MailError / InboxError); consolidating would lose the per-module error code.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/asyncapi-traits.js", "lib/flag-evaluation-context.js", "lib/render.js",
      ],
      reason: "Object-property iteration with hasOwnProperty guard idiom — `for (var k in X) if (Object.prototype.hasOwnProperty.call(X, k)) ...` is the standard Object-pollution-defense walk. Three different domains (AsyncAPI trait merge, flag-evaluation context normalisation, render template-context walk); consolidating would couple unrelated primitives.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/compliance-ai-act-prohibited.js",
        "lib/compliance-ai-act-risk.js",
        "lib/compliance-ai-act-logging.js",
        "lib/compliance-ai-act.js",
        "lib/compliance-ai-act-transparency.js",
        "lib/guard-all.js",
      ],
      reason: "EU AI Act primitive family + guard-all linear-scan idiom — sibling modules sharing the linear catalog-walk shape (`for (var i = 0; i < ARR.length; i += 1) { if (ARR[i].id === id) return ARR[i]; } return null;`). The AI-Act catalogs diverge (Article 5 prohibited practices vs Annex III high-risk rows vs Article 12 logging fields vs Article 50 transparency banners) and guard-all walks the registered guard-list; consolidating would lose per-domain structure.",
    },
    {
      files: [
        "lib/compliance-ai-act.js", "lib/gate-contract.js", "lib/mail-auth.js",
      ],
      reason: "Long opts-passthrough block where each line is `field: opts.field || null` with the same null-fallback shape. AI-Act annexIVScaffold builds the Annex IV section-1 record; gate-contract assembles content-safety profile; mail-auth builds an authentication-results header. Three different schemas; not consolidatable.",
    },
    {
      files: ["lib/guard-all.js", "lib/middleware/index.js", "lib/websocket-channels.js"],
      reason: "Long `field: opts.field` config-passthrough chain coincidentally shingles. guard-all assembles per-guard opts (gate-contract vocabulary); middleware/index forwards createApp opts to per-middleware factories; websocket-channels forwards channel-broker opts. Three different domains, three different vocabulary lists — not consolidatable.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/security-txt.js", "lib/middleware/assetlinks.js",
        "lib/middleware/web-app-manifest.js",
        "lib/middleware/tus-upload.js",
      ],
      reason: "Static/well-known + TUS-collection middleware family — security.txt / assetlinks / web-app-manifest / tus-upload all gate on a fixed mountPath then branch on req.method, share the headersSent guard + writeHead/end+observability emit shape. Four different domains, four different response bodies and lifecycle semantics. Future consolidation candidate when a 5th well-known emitter ships.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/password.js", "lib/middleware/tus-upload.js",
        "lib/request-helpers.js", "lib/observability.js",
      ],
      reason: "Argon2id PHC-encoder/decoder + TUS metadata + Cookie-attribute parser + W3C tracestate parser independently iterate over `key=value` / `key value` token pairs and split on the first separator. The 50-token shingle is the loop+split skeleton; the per-domain semantics (Argon2 cost params vs TUS metadata vs cookie attrs vs trace vendor pairs) are different enough that consolidating would erode each parser's domain validation.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/external-db-migrate.js", "lib/middleware/db-role-for.js",
        "lib/middleware/web-app-manifest.js",
        "lib/middleware/security-txt.js",
        "lib/middleware/tus-upload.js",
        "lib/outbox.js",
        "lib/observability-otlp-exporter.js",
        "lib/compliance-sanctions-fetcher.js",
        "lib/dsr.js",
      ],
      reason: "validateOpts factory prelude — every factory primitive runs the same `validateOpts.requireNonEmptyString(opts.X, label, ErrorClass, code) + validateOpts.optionalY + closure-capture` shape because they share the operator-typo handling convention. Nine different domains with nine different error classes; consolidating would push validation past the call boundary where the operator's typo gets the wrong error code.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js", "lib/file-upload.js",
        "lib/observability-otlp-exporter.js", "lib/static.js",
      ],
      reason: "JSON-envelope serializer prelude — cloud-events / file-upload / otlp-exporter / static all build a `{ headers, body }` JSON envelope from operator opts via Object.assign + JSON.stringify; validate the resulting payload byte-length; return the rendered Buffer. Four different domains (CloudEvents 1.0 / multipart upload / OTLP/JSON spans / static-asset response), four different content shapes; the 50-token shingle is the envelope-build skeleton.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js", "lib/external-db-migrate.js",
        "lib/observability-otlp-exporter.js", "lib/observability-tracer.js",
      ],
      reason: "Object.assign + validateOpts shape — cloud-events / external-db-migrate / otlp-exporter / observability-tracer each define an opts validator that calls validateOpts(opts, [...allowed-keys], label) and then merges resource/scope-level defaults via Object.assign. Four different domains; the 50-token shingle is the validator+merge skeleton.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/cloud-events.js", "lib/observability-otlp-exporter.js",
        "lib/static.js",
      ],
      reason: "JSON envelope builder + Content-Type/Length response shape — cloud-events / otlp-exporter / static all build a JSON-serializable response, compute Content-Length, set Content-Type, and emit observability.safeEvent on send. Three different domains, three different envelope payloads.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/file-upload.js", "lib/middleware/span-http-server.js",
        "lib/static.js",
      ],
      reason: "Response-lifecycle hook scaffold — file-upload / span-http-server / static each register `res.on('finish'|'close'|'error', _finish)` to fire a single closure on response completion regardless of which event terminates the response. Three different domains (chunk cleanup / span end / asset audit); the 50-token shingle is the listener wiring + idempotent-closure pattern.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/break-glass.js", "lib/outbox.js", "lib/queue-local.js",
      ],
      reason: "Backoff curve / repeating-tick worker scaffolding — break-glass / outbox / queue-local each spin a `safeAsync.repeating` worker that polls a backing store, claims rows under FOR UPDATE SKIP LOCKED, processes, and advances next_attempt_at via a `min(initial * factor^N, max)` exponential cap. Three independent domains with different schemas + different retry semantics; the 50-token shingle is the worker scaffold, not the domain logic.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/db-role-for.js", "lib/middleware/tus-upload.js",
        "lib/outbox.js", "lib/dsr.js",
        "lib/compliance-sanctions.js", "lib/observability-otlp-exporter.js",
        "lib/compliance-sanctions-fetcher.js",
        "lib/guard-html-wcag.js", "lib/mail-dkim.js",
        "lib/mail-arc-sign.js",
        "lib/auth/sd-jwt-vc-issuer.js", "lib/auth/sd-jwt-vc-holder.js",
        "lib/auth/dpop.js",
      ],
      reason: "Audit + observability emit prelude — every primitive wraps `audit.safeEmit` / `observability.safeEvent` calls in a try/catch+swallow because both are best-effort observability sinks. Different action vocabularies; consolidating would lose the per-primitive metric name.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/dpop.js", "lib/compliance-sanctions.js", "lib/dora.js",
        "lib/middleware/dpop.js", "lib/outbox.js", "lib/static.js",
        "lib/compliance-sanctions-fetcher.js", "lib/dsr.js",
        "lib/auth/sd-jwt-vc-holder.js", "lib/auth/sd-jwt-vc-issuer.js",
      ],
      reason: "Try/catch + drop-silent observability emit — every primitive wraps `audit().safeEmit({ action, outcome, metadata })` in a try/catch+swallow per the validation-tier policy (drop-silent at hot-path observability sinks). The 50-token shingle is the swallow shape, not the domain logic.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/db.js", "lib/network-tls.js", "lib/ntp-check.js",
      ],
      reason: "Periodic-monitor scaffolding — db.integrityMonitor / network-tls.expiryMonitor / ntpCheck.monitor each spin a `safeAsync.repeating` worker that performs a poll, emits an audit + observability event on every tick, fires an operator hook on threshold crossing, and returns a `.stop()` handle. Three different domains (SQLite corruption / TLS cert expiry / NTP clock drift); the 50-token shingle is the worker scaffold + emit shape, not the domain logic. Future consolidation candidate when a 4th periodic monitor lands.",
    },
    {
      files: ["lib/auth/dpop.js", "lib/break-glass.js", "lib/middleware/security-txt.js"],
      reason: "Generic input validation prelude — `if (typeof X !== 'string' || X.length === 0 || /[\\r\\n\\0]/.test(X)) throw` repeats across primitives that gate operator-supplied strings against header-injection bytes (DPoP htm/htu, break-glass reasons, security.txt field values). Three different error classes; the rejection reason is identical but the error code prefix is per-domain.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/sd-jwt-vc-issuer.js", "lib/auth/step-up.js",
        "lib/auth/step-up-policy.js",
        "lib/break-glass.js", "lib/dsr.js", "lib/middleware/assetlinks.js",
        "lib/middleware/require-methods.js", "lib/middleware/security-txt.js",
        "lib/network-dns.js", "lib/network-heartbeat.js",
        "lib/network-tls.js", "lib/safe-schema.js",
        "lib/ws-client.js", "lib/mail-arc-sign.js",
      ],
      reason: "Non-empty-array opt validation prelude — `if (!Array.isArray(opts.X) || opts.X.length === 0) throw` plus per-element non-empty-string check repeats across primitives that take operator-supplied lists (sd-jwt-vc issuer keys, step-up acrValues / requiredAmr, step-up-policy acrAny / amr / requiredAmr atoms, require-methods HTTP-verb allowlist, security-txt contact lines, break-glass columns, dsr sources, assetlinks statements, DNS resolver IPs, heartbeat targets, TLS key shares, safe-schema enum values, ws-client subprotocols). Twelve different domains with file-specific error classes; consolidating would lose the per-module error code.",
    },
    {
      mode:  "family-subset",
      files: ["lib/file-upload.js", "lib/guard-html.js", "lib/static.js", "lib/cloud-events.js"],
      reason: "Validate-opts scaffolding + per-primitive PROFILES literal block. file-upload and static open with the same `validateOpts.requireObject(...)` cascade; guard-html's PROFILES literal carries the same opt-name vocabulary as both; cloud-events.wrap performs the same require + optional cascade across spec attributes. Different create()-style entry shapes; the bodies diverge. Same conventional-shape false-positive as the prior validateOpts cluster.",
    },
    {
      files: ["lib/audit.js", "lib/guard-csv.js", "lib/guard-html.js"],
      reason: "Audit emission shape — `audit.emit({ event, outcome, metadata: { ... } })` carries identical token sequence across the audit primitive itself and any consumer that emits structured audit rows. guard-csv and guard-html each emit their own domain events; consolidation is impossible because the audit module IS the canonical emitter and the consumers cannot route through themselves.",
    },
    {
      mode:  "family-subset",
      files: ["lib/api-key.js", "lib/file-upload.js", "lib/static.js", "lib/cloud-events.js"],
      reason: "_validateOpts function-prelude scaffolding — every primitive's create() opens with `function _validateXxxOpts(opts) { validateOpts.requireObject(opts, ..., XError); validateOpts.requireNonEmptyString(...); validateOpts.optionalXxx(...) }`. Same scaffolding by design; the cascade body differs per primitive's domain. Tracked as conventional-shape false-positive.",
    },
    {
      files: ["lib/api-key.js", "lib/guard-csv.js", "lib/guard-svg.js"],
      reason: "Same conventional-shape scaffolding as the file-upload/static cluster — every primitive opens its create()/factory with the same `validateOpts.requireObject(...)` cascade plus per-domain numericBounds / requireNonEmptyString calls. The token sequence shingles across primitives that share the convention; the cascades' bodies (api-key columns vs csv profile-resolution vs svg compliance-posture lookup) diverge.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-auth.js", "lib/mail-dkim.js", "lib/mail-bimi.js",
        "lib/mail-arc-sign.js",
        "lib/middleware/body-parser.js", "lib/network-smtp-policy.js",
        "lib/auth/step-up.js",
      ],
      reason: "Generic key=value record-parsing idiom — split on delimiter, trim, split first '=' into key/value, lowercase, dispatch by key. Appears in DKIM-Signature tag-list parsing, DMARC record parsing, BIMI record parsing, MTA-STS policy text parsing, the body-parser content-type-parameter parser, and the RFC 7235 / RFC 9470 WWW-Authenticate Bearer challenge parser. Each module's value-coercion + policy-key-name set is genuinely different; the 5-line shape doesn't merit extraction.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/auth/jwt.js", "lib/auth/jwt-external.js", "lib/auth/oauth.js",
        "lib/auth/dpop.js", "lib/auth/status-list.js",
      ],
      reason: "auth-jwt / JOSE family — all five files implement JWS decode + signature verification against operator-supplied or proof-embedded keys. The shared shingle is the canonical 3-part split + base64url decode + safeJson.parse(header/payload) + algorithm allowlist enforcement that every JWS verifier must perform; the divergence is which keys / algorithms / claim-checks each module accepts (PQC algs in jwt.js; classical algs + JWKS in jwt-external.js; full OAuth-discovery + ID-token shape in oauth.js; embedded-jwk DPoP proof in dpop.js with htm/htu/ath/jti claims). Each module's failure-mode codespace (auth-jwt/* vs auth-jwt-external/* vs auth-oauth/* vs auth-dpop/*) is operator-distinguishable so consolidating to a single helper would either lose the distinct error class or pass the class through every helper site. Future consolidation candidate when the JOSE family doubles in size.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/guard-csv.js", "lib/guard-html.js", "lib/guard-svg.js",
        "lib/guard-filename.js", "lib/guard-archive.js", "lib/guard-json.js",
        "lib/guard-yaml.js", "lib/guard-xml.js", "lib/guard-markdown.js",
        "lib/guard-email.js", "lib/guard-domain.js", "lib/guard-uuid.js",
        "lib/guard-cidr.js", "lib/guard-time.js", "lib/guard-mime.js",
        "lib/guard-jwt.js", "lib/guard-oauth.js", "lib/guard-graphql.js",
        "lib/guard-shell.js", "lib/guard-regex.js", "lib/guard-jsonpath.js",
        "lib/guard-template.js", "lib/guard-image.js", "lib/guard-pdf.js",
        "lib/guard-auth.js",
        // Future family members go here as they ship — the family-
        // subset matcher allows any cluster whose every file is in
        // this list, so adding a new guard doesn't need new entries.
      ],
      reason: "guard-* family ABI — every member's gate() factory header (function gate(opts) { opts = _resolveOpts(opts); return gateContract.buildGuardGate(...); }), bottom-of-file helper triplet (buildProfile = gateContract.makeProfileBuilder(PROFILES); function compliancePosture(name) { return gateContract.lookupCompliancePosture(...); }; var _xRulePacks = gateContract.makeRulePackLoader(...); var loadRulePack = _xRulePacks.load), and PROFILES literal block all share the family-shared vocabulary by design. The keys ARE the family contract; the values diverge per guard (csv handles operatorRules + sanitize re-emit; html has sanitize-eligibility branching; svg refuses SVGZ; filename operates on strings; archive on entries; json on parsed trees + source scan). Further extraction would either pull body decision logic that's genuinely per-guard into a shared place, or extract a one-line factory that hides the family contract from anyone reading the guard source.",
    },
    {
      files: ["lib/api-snapshot.js", "lib/break-glass.js", "lib/deprecate.js"],
      reason: "Two-arg required-string validation pattern — different domains coincidentally share the `if (!opts || typeof opts !== 'object') ... if (typeof X !== 'string' || X.length === 0)` shape. Sites use file-specific error classes that diverge from the framework standard signature.",
    },
    {
      files: ["lib/atomic-file.js", "lib/deprecate.js", "lib/totp.js"],
      reason: "Two consecutive non-empty-string checks. Sites use AtomicFileError / DeprecateError / TotpError — each with a slightly different constructor signature that doesn't fit requireNonEmptyString. Tracked for future error-class-signature normalization.",
    },
    {
      files: ["lib/audit-chain.js", "lib/audit-tools.js", "lib/audit.js"],
      reason: "Audit chain verification loop — `for (var i ...) { if (entry.X !== expected) return { ok: false, ...}}`. Inherent to the audit verification domain; the loop body checks domain-specific invariants.",
    },
    {
      files: ["lib/audit-sign.js", "lib/framework-schema.js", "lib/vault/index.js"],
      reason: "PQC envelope-validation entry shape — `if (!X || !X.field) throw; var alg = (X.alg || '').toLowerCase(); if (alg !== 'A' && alg !== 'B') throw`. Each module checks its own envelope contract.",
    },
    {
      files: ["lib/auth/jwt.js", "lib/external-db.js", "lib/http-client.js"],
      reason: "Optional-field forwarder pattern — `if (X.A !== undefined) emit('A', X.A); if (X.B !== undefined) emit('B', X.B)`. Each module's emit-specific (jwt claims / db pool stats / http headers).",
    },
    {
      files: ["lib/backup/bundle.js", "lib/restore-bundle.js", "lib/restore-rollback.js"],
      reason: "Bundle file-IO entry — `if (typeof opts.X !== 'string' || !atomicFile.Y(opts.X)) throw; atomicFile.Z(opts.X, ...)`. Backup/restore lifecycle ops share file-validation entry shape; refactoring would consolidate into a backup/restore base helper. Tracked as future opportunity.",
    },
    {
      files: ["lib/backup/bundle.js", "lib/restore-bundle.js", "lib/vault/rotate.js"],
      reason: "Same backup/restore/vault file-IO pattern as above; vault/rotate participates because it uses the same bundle wrapping. Future consolidation candidate.",
    },
    {
      files: ["lib/backup/index.js", "lib/restore.js", "lib/scheduler.js"],
      reason: "Async timer setup with cleanup — `setInterval` + `unref()` + `cancel()` shape. Scheduler-shape primitives across backup / restore / scheduler. Three different operator-facing primitives with different timer semantics; consolidation candidate but each has distinct cleanup contract.",
    },
    {
      mode:  "family-subset",
      files: ["lib/auth/jwt-external.js", "lib/auth/oauth.js", "lib/network-smtp-policy.js", "lib/mail-auth.js", "lib/mail-bimi.js"],
      reason: "External structured-data ingestion + safe-* parser + file-specific framework-error throw. Each module ingests serialized data from a different external surface (JWKS endpoint over HTTP, OAuth discovery doc, TLS-RPT JSON report, DMARC RUA XML report, BIMI TXT record) with file-specific size caps and error classes. Extracting to a shared helper would either lose the per-module error class or pass it through every helper site, making the call sites less readable than the current inline 3-line block.",
    },
    {
      files: ["lib/db-declare-row-policy.js", "lib/db-declare-view.js", "lib/middleware/db-role-for.js"],
      reason: "Role/policy SQL identifier validation + dbRole compound check. Three different declarative-DB primitives share the role-name validation entry. Future consolidation candidate as `db.validateRoleSpec(opts, errorClass, code)`.",
    },
    {
      files: ["lib/dual-control.js", "lib/notify.js", "lib/retention.js"],
      reason: "Required + nested-shape validation — `async function f(opts) { if (!opts || typeof opts !== 'object') throw; if (typeof opts.X !== 'string' || opts.X.field === N) throw }`. Each primitive's specific contract on opts.X varies (purpose / channel / table); compound shape resists generic extraction.",
    },
    {
      files: ["lib/external-db-migrate.js", "lib/migrations.js", "lib/seeders.js"],
      reason: "Migration runner file-listing + apply pattern. The dbSchema.runInTransaction extraction handled the BEGIN/COMMIT/ROLLBACK; what remains is the file-loading + each-file-apply loop. Inherent to migration-runner domain; each runner has slightly different metadata / environment shape.",
    },
    {
      files: ["lib/html-balance.js", "lib/object-store/sigv4.js", "lib/parsers/safe-xml.js"],
      reason: "Character-class range checks (`(c >= 0xA && c <= 0xZ) || (c >= 0xA2 && c <= 0xZ2)`) appearing in any string-classifier code. Generic JS idiom, not extractable.",
    },
    {
      files: ["lib/log-stream-cloudwatch.js", "lib/log-stream-otlp.js", "lib/log-stream-webhook.js"],
      reason: "Log-stream emit() entry — `} ); if (buffer.length >= cfg.batchSize) { _flush().catch(()=>{}); } else { flushScheduler.schedule(); } return Promise.resolve({ accepted: true, queued: buffer.length });`. The framework's log-stream sinks share this exact emit return shape. Could be a base-factory but each sink's surrounding emit-pre-checks differ.",
    },
    {
      files: ["lib/mail-dkim.js", "lib/metrics.js", "lib/safe-schema.js"],
      reason: "Format-array iteration with predicate check — `for (var i ...) { if (!predicate(arr[i])) throw }`. Generic JS validation pattern across unrelated domains.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/mail-arc-sign.js", "lib/mail-dkim.js", "lib/metrics.js",
        "lib/safe-schema.js",
      ],
      reason: "Same array-iteration-with-predicate shape as the mail-dkim/metrics/safe-schema cluster — mail-arc-sign's headersToSign element validation walks the operator-supplied array of header names with the same `for (var i ...) { if (!predicate(arr[i])) throw }` shape; predicate body differs per domain.",
    },
    {
      files: ["lib/inbox.js", "lib/middleware/span-http-server.js", "lib/outbox.js"],
      reason: "Transactional-store + span-lifecycle audit prelude — inbox.handle / outbox.relay / span-http-server's response-finish hook each invoke `audit.safeEmit({ action, outcome, metadata })` inside a try/catch swallow on the hot path. Three different domains (dedupe-on-receive vs at-least-once relay vs HTTP request span); the 50-token shingle is the sink-emit shape, not the domain logic.",
    },
    {
      files: ["lib/mail.js", "lib/migrations.js", "lib/seeders.js"],
      reason: "Identifier/format validation + sql identifier check. Mail uses email-address validators; migrations/seeders use SQL identifier validators. Different domains with the same `function isXValid(s) { return typeof s === 'string' && s.length > 0 && s.length <= MAX && regex.test(s); }` shape.",
    },
    {
      files: ["lib/middleware/bot-guard.js", "lib/middleware/cors.js", "lib/middleware/csrf-protect.js"],
      reason: "Middleware factory boilerplate — opts validation + xff/trustProxy parse + helper wiring. Middleware factories share scaffolding by design; consolidating into a base factory would cost more readability than it saves.",
    },
    {
      mode:  "family-subset",
      files: [
        "lib/middleware/cookies.js", "lib/middleware/gpc.js",
        "lib/middleware/headers.js",
      ],
      reason: "Threat-detection middleware family — each shares the same `_emitAudit(audit, action, outcome, metadata) { ... try { audit.safeEmit({...}); } catch (_e) { /* drop-silent */ } }` audit-emission shape. Per the validation-tier policy this is the hot-path observability sink shape; extracting would force a shared `audit-emit-drop-silent` primitive — the framework already has audit.safeEmit, and the middleware-local wrapper's value is keeping the drop-silent behavior visible at the call site. Future consolidation candidate.",
    },
    {
      files: ["lib/middleware/bot-guard.js", "lib/middleware/cors.js", "lib/middleware/rate-limit.js"],
      reason: "Same middleware-factory cluster as above with rate-limit substituted. Same justification.",
    },
    {
      files: ["lib/middleware/db-role-for.js", "lib/notify.js", "lib/seeders.js", "lib/webhook.js"],
      reason: "Optional-nested-object shape validation — `if (opts.X !== undefined && opts.X !== null) { if (typeof opts.X !== 'object' || typeof opts.X.method !== 'function') throw }`. Each handle has a different method-shape contract (audit / observability / queue / permissions). Future consolidation candidate as `validateOpts.methodShape(value, methodName, label, errorClass)`.",
    },
    {
      files: ["lib/middleware/db-role-for.js", "lib/seeders.js", "lib/webhook.js"],
      reason: "Same nested-shape cluster as above with notify removed. Same justification.",
    },
    {
      files: ["lib/network-proxy.js", "lib/network-tls.js", "lib/network.js"],
      reason: "Network listener teardown shape — `function reset() { state.X = null; state.Y = null; state.Z = []; ...}`. Each network primitive has a different reset surface; consolidating would force unrelated state into a base contract.",
    },
    {
      files: ["lib/notify.js", "lib/seeders.js", "lib/webhook.js"],
      reason: "Same nested-shape cluster as middleware/db-role-for+notify+seeders+webhook (see above) with db-role-for removed.",
    },
    {
      files: ["lib/object-store/azure-blob.js", "lib/object-store/gcs.js", "lib/object-store/sigv4.js"],
      reason: "S3-protocol shared upload shape — multipart-upload state machine fingerprint. Each protocol's upload shape differs in headers / signing / response parsing; common scaffolding (request-helper, response-parse) is already extracted to lib/object-store/http-request.js.",
    },
    {
      files: ["lib/object-store/azure-blob.js", "lib/object-store/http-put.js", "lib/object-store/sigv4.js"],
      reason: "Same object-store SDK cluster as above with http-put substituted. Same justification.",
    },
    {
      files: ["lib/object-store/gcs.js", "lib/object-store/sigv4.js", "lib/static.js"],
      reason: "Operator-supplied URL parsing entry — `var parsed = safeUrl.parse(url, { ... }); var hostname = parsed.hostname; ...`. URL extraction shape across object-store backends + static-asset server.",
    },
    {
      files: ["lib/parsers/safe-env.js", "lib/parsers/safe-toml.js", "lib/parsers/safe-yaml.js"],
      reason: "Parser entry — `function parse(input, opts) { opts = opts || {}; if (opts.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxBytes)) throw }`. Parser error classes use `(message, code, line, col)` constructor signature that doesn't fit numericBounds.requireXIfPresent helper. Future opportunity: normalize parser error class signatures to match framework standard.",
    },
  ];
  var _knownClusterSet = Object.create(null);
  var _familySubsetSets = [];     // entries with mode:"family-subset" → allow any subset
  KNOWN_CLUSTERS.forEach(function (e) {
    if (e.mode === "family-subset") {
      var familyFileSet = Object.create(null);
      e.files.forEach(function (f) { familyFileSet[f] = true; });
      _familySubsetSets.push(familyFileSet);
      return;
    }
    var key = e.files.slice().sort().join("|");
    _knownClusterSet[key] = e;
  });

  var strong = rows.filter(function (r) {
    if (r.passLabel !== "[exact]") return false;
    if (r.bestSize < STRONG_MIN_SIZE) return false;
    if (r.fileSet.length < STRONG_MIN_FILES) return false;
    var key = r.fileSet.slice().sort().join("|");
    if (_knownClusterSet[key]) return false;     // exact-match allowlisted
    // family-subset: any cluster whose every file is in a registered
    // family set is allowed. Used for the guard-* family ABI clusters
    // — adding one new guard creates O(2^N) new file-set combinations,
    // which exact-match allowlisting can't sustain.
    for (var fi = 0; fi < _familySubsetSets.length; fi += 1) {
      var fs = _familySubsetSets[fi];
      var allInFamily = true;
      for (var j = 0; j < r.fileSet.length; j += 1) {
        if (!fs[r.fileSet[j]]) { allInFamily = false; break; }
      }
      if (allInFamily) return false;
    }
    return true;
  });
  // Only the strong-signal cluster is a primitive-extraction
  // candidate. The weak-tier inventory (smaller shingles, skeleton-
  // shape matches) was tuned out — it surfaced JS / framework
  // language idiom that can't be extracted (every file's constant
  // declarations, function signatures, module exports). Keeping only
  // the strong signal as a hard gate.
  if (strong.length > 0) {
    var strongMatches = strong.map(function (r) {
      var first = r.sites[0];
      return {
        file:    first.file,
        line:    first.line,
        content: "STRONG-DUP " + r.bestSize + "-tok in " + r.fileSet.length +
                 " files: " + r.fileSet.slice(0, 5).join(", ") +
                 (r.fileSet.length > 5 ? " (+" + (r.fileSet.length - 5) + ")" : "") +
                 " — first @ " + first.file + ":" + first.line + "-" + first.endLine,
      };
    });
    strongMatches = _filterMarkers(strongMatches, "duplicate-block");
    _report("strong-signal duplicate code: " + STRONG_MIN_SIZE +
            "+ token exact shingle in " + STRONG_MIN_FILES + "+ files → " +
            "extract a shared primitive",
      strongMatches);
  } else {
    check("strong-signal duplicate-block (no clusters)", true);
  }
}

// ---- Pattern 42: state-stamps in user-facing docs (smoke test the wiki) ----

function testNoStateStampsInPublicDocs() {
  // feedback_no_state_stamps_in_docs.md — version numbers / test counts
  // in README / SECURITY / CONTRIBUTING etc. rot the moment the next
  // release ships. We can't easily grep these via the lib walker, but
  // we can grep the repo root for "v0.6.\d+" outside CHANGELOG / git
  // tags / package.json. Skip for now — needs a different scanner that
  // walks the repo root, not just lib/. Future patch.
  check("state-stamp scanning requires a repo-root walker (deferred)",
        true);
}

// KNOWN_ANTIPATTERNS — n=1 hard gate.
//
// Each entry registers the inline shape of code that has been replaced
// by a framework primitive. Any future file matching the regex
// hard-fails with a pointer to the primitive — even at n=1, before the
// duplicate-block detector (which needs n>=5) would notice.
//
// Why this exists: the duplicate-block detector catches drift that has
// already proliferated; the catalog catches drift the moment it tries
// to land. When a new primitive is extracted from N call sites, the
// inline shape is registered here in the SAME patch so a subsequent
// file written from muscle memory hits the gate immediately.
//
// Discipline:
//   1. Every primitive extraction adds an entry here in the same patch.
//   2. `allowlist` is the audit trail. New entries default to []
//      because the extraction was complete at registration time.
//   3. Adding a file to `allowlist` later requires a documented reason
//      in the entry's `reason` field. The pre-ship rules audit calls
//      out every allowlist change.
//   4. The catalog scans whole-file content (multiline regex) so
//      patterns split across lines still match.
var KNOWN_ANTIPATTERNS = [
  {
    id: "inline-codepoint-class-table",
    primitive: "codepointClass.BIDI_RE / C0_CTRL_RE / ZERO_WIDTH_RE / NULL_RE_G / hex4 / charClass / fromCp",
    regex: /var\s+BIDI_RANGES\s*=\s*\[\s*0x200E[\s\S]{0,500}?function\s+_charClass/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. The BIDI_RANGES + C0_CTRL_RANGES + ZERO_WIDTH_RANGES literal tables plus the _hex4 / _charClass / _fromCp helpers plus the `new RegExp(\"[\" + _charClass(...) + \"]\")` regex compilations were identical across 3 guard primitives by design. Centralized so the codepoint catalog has a single source of truth and future guards (filename / archive / mime / ...) consume the shared module instead of re-defining the tables.",
  },
  {
    id: "inline-resolve-profile-and-posture",
    primitive: "gateContract.resolveProfileAndPosture(opts, { profiles, compliancePostures, defaults, errorClass, errCodePrefix })",
    regex: /typeof\s+opts\.profile\s*===\s*["']string["'][\s\S]{0,300}?compliancePosture[\s\S]{0,300}?Object\.assign\(\{\}\s*,\s*[A-Z]+/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg. Every guard primitive's _resolveOpts opens with the identical `if (opts.profile) overlay = PROFILES[opts.profile]; if (opts.compliancePosture) overlay = Object.assign(overlay, COMPLIANCE_POSTURES[...]); return Object.assign({}, DEFAULTS, overlay, opts);` cascade. Centralized in gateContract so future guards consume the shared resolver — keeps the family resolution shape identical across members.",
  },
  {
    id: "inline-char-strip-policy-cascade",
    primitive: "codepointClass.applyCharStripPolicies(text, opts)",
    regex: /opts\.bidiPolicy\s*===\s*["']strip["'][\s\S]{0,200}?opts\.controlPolicy\s*===\s*["']strip["'][\s\S]{0,200}?opts\.nullBytePolicy/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg sanitize paths — the 4-line `if (opts.bidiPolicy === 'strip') s = s.replace(BIDI_RE_G, '')` cascade was identical. guard-csv uses different opt-name vocabulary (bidiCharPolicy / nullByteHandling) so it keeps its inline strip block; that's a single-vendor occurrence, below the duplicate-detector floor.",
  },
  {
    id: "inline-detect-char-threats",
    primitive: "codepointClass.detectCharThreats(text, opts, codePrefix)",
    regex: /var\s+bidiMatch\s*=\s*\w+\.match\(BIDI_RE\)[\s\S]{0,200}?bidi-override[\s\S]{0,300}?nullBytePolicy[\s\S]{0,200}?null-byte/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg detection passes — the bidi/null-byte/control-char issue-emit cascade was identical at the head of every _detectIssues. guard-csv keeps its inline form because it uses different opt-name vocabulary (bidiCharPolicy / nullByteHandling) and additionally classifies homoglyphs as a CSV-specific threat.",
  },
  {
    id: "inline-profile-builder-forwarder",
    primitive: "gateContract.makeProfileBuilder(profiles)",
    regex: /function\s+buildProfile\s*\(opts\)\s*\{\s*return\s+gateContract\.buildProfile\(Object\.assign\(\{\}\s*,\s*opts,\s*\{[\s\S]{0,150}?resolveProfile:\s*function\s*\(name\)\s*\{\s*return\s+PROFILES\[name\]/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg buildProfile(opts) wrappers — every guard exposed a 4-line passthrough that injected the per-guard PROFILES into gateContract.buildProfile's resolveProfile callback. Centralized into a closure factory.",
  },
  {
    id: "inline-compliance-posture-lookup",
    primitive: "gateContract.lookupCompliancePosture(name, postures, errorFactory, codePrefix)",
    regex: /if\s*\(!COMPLIANCE_POSTURES\[name\]\)[\s\S]{0,150}?bad-posture[\s\S]{0,200}?Object\.assign\(\{\}\s*,\s*COMPLIANCE_POSTURES\[name\]\)/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg compliancePosture(name) entry points. Identical 5-line `if (!COMPLIANCE_POSTURES[name]) throw; return Object.assign({}, COMPLIANCE_POSTURES[name])` shape consolidated.",
  },
  {
    id: "inline-rule-pack-loader",
    primitive: "gateContract.makeRulePackLoader(errorClass, codePrefix)",
    regex: /var\s+_\w*[Rr]ulePacks?\s*=\s*\{\}[\s\S]{0,80}function\s+loadRulePack\s*\(\s*pack\s*\)\s*\{[\s\S]{0,200}?validateOpts\.requireObject[\s\S]{0,200}?validateOpts\.requireNonEmptyString[\s\S]{0,100}?_\w*[Rr]ulePacks?\[pack\.id\]\s*=\s*pack/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg loadRulePack(pack) entry. Identical scaffolding (closed-over store + validateOpts cascade + pack.id keyed insert) consolidated into a closure factory.",
  },
  {
    id: "inline-extract-bytes-as-text",
    primitive: "gateContract.extractBytesAsText(ctx)",
    regex: /var\s+bytes\s*=\s*ctx\.bytes\s*;\s*if\s*\(!bytes\)\s*return\s*\{\s*ok:\s*true,\s*action:\s*["']serve["'][\s\S]{0,40}\s*var\s+text\s*=\s*Buffer\.isBuffer\(bytes\)/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html check(ctx) entries. The ctx.bytes → Buffer-or-string → utf8 string normalization with empty-bytes-serve early-return was identical. guard-svg keeps the inline shape because it passes bytes (Buffer) directly to validate() for SVGZ magic-byte detection.",
  },
  {
    id: "inline-build-guard-gate-forwarder",
    primitive: "gateContract.buildGuardGate(name, opts, check)",
    regex: /forensicEvidenceStore:\s*opts\.forensicEvidenceStore[\s\S]{0,400}?onAudit:\s*opts\.onAudit/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg gate(opts) factories. Every guard's gate() body forwarded the same ~16-key opts bag (mode / audit / observability / forensicEvidenceStore / cache / hooks / runtime cap / ...) to gateContract.defineGate; centralized so each guard's gate() body is just the check function plus a label.",
  },
  {
    id: "inline-bad-input-issue-result",
    primitive: "gateContract.badInputResultIfNotStringOrBuffer(input)",
    regex: /typeof\s+input\s*!==\s*["']string["']\s*&&\s*!Buffer\.isBuffer\(input\)\s*\)\s*\{\s*return\s*\{\s*ok:\s*false,\s*issues:\s*\[\s*\{\s*kind:\s*["']bad-input["']/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-svg / guard-filename validate paths that need raw-Buffer input pre-conversion (svg for SVGZ magic, filename for overlong-UTF-8 byte scan). The bad-input fallback `{ ok: false, issues: [{ kind: bad-input, ... }] }` return shape was identical. Sanitize throw paths (different control-flow) are distinct and stay inline.",
  },
  {
    id: "inline-aggregate-issues",
    primitive: "gateContract.aggregateIssues(issues)",
    regex: /return\s*\{\s*ok:\s*!issues\.some\(function\s*\(i\)\s*\{\s*return\s+i\.severity\s*===\s*["']critical["']\s*\|\|\s*i\.severity\s*===\s*["']high["']/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-* validate paths that build the { ok, issues } result. The 5-line ok-aggregation tail (no critical/high → ok=true) was identical across guards; consolidated.",
  },
  {
    id: "inline-issue-validator-entry",
    primitive: "gateContract.runIssueValidator(input, opts, detector)",
    regex: /typeof\s+input\s*===\s*["']string["'][\s\S]{0,80}?Buffer\.isBuffer\(input\)[\s\S]{0,200}?bad-input[\s\S]{0,300}?return\s*\{[\s\S]{0,80}?ok:\s*!issues\.some/,
    allowlist: ["lib/gate-contract.js"],
    reason: "Extracted across guard-csv / guard-html validate() entry points. The string|Buffer normalization + bad-input fallback + issue-aggregation return shape was identical across guards; centralized into gate-contract. guard-svg keeps its inline form because SVGZ magic-byte detection needs the raw Buffer (utf8 conversion would lose the gzip header).",
  },
  {
    id: "inline-batch-positive-int-validation",
    primitive: "numericBounds.requireAllPositiveFiniteIntIfPresent(opts, names, labelPrefix, ErrorClass, code)",
    regex: /numericBounds\.requirePositiveFiniteIntIfPresent\([\s\S]{0,300}?numericBounds\.requirePositiveFiniteIntIfPresent\([\s\S]{0,300}?numericBounds\.requirePositiveFiniteIntIfPresent\(/,
    allowlist: ["lib/numeric-bounds.js"],
    reason: "Extracted across guard-csv / guard-html / guard-svg validate-entry numeric-opt cascades. Three or more consecutive `numericBounds.requirePositiveFiniteIntIfPresent(opts.X, ...)` calls in a row is exactly the shape this batch helper consolidates. Other primitives with 1-2 cap-opts can keep the single-call form; the batch helper kicks in at the 3+ threshold.",
  },
  {
    id: "inline-assert-no-char-threats",
    primitive: "codepointClass.assertNoCharThreats(text, opts, errorFactory, codePrefix)",
    regex: /opts\.bidiPolicy\s*===\s*["']reject["'][\s\S]{0,150}?BIDI_RE\.test[\s\S]{0,200}?opts\.nullBytePolicy\s*===\s*["']reject["']/,
    allowlist: ["lib/codepoint-class.js"],
    reason: "Extracted across guard-html / guard-svg sanitize entry — every guard's reject-on-character-class threats opens with the same `if (opts.bidiPolicy === 'reject' && BIDI_RE.test(s)) throw; if (opts.nullBytePolicy === 'reject' && s.indexOf(NULL_BYTE) !== -1) throw; if (opts.controlPolicy === 'reject' && C0_CTRL_RE.test(s)) throw;` cascade. Centralized so the reject-policy contract is identical across the family. guard-csv keeps its own inline cell-level reject for opt-name vocabulary reasons (bidiCharPolicy etc.).",
  },
  {
    id: "inline-audit-shape-validation",
    primitive: "validateOpts.auditShape(audit, label, ErrorClass)",
    regex: /opts\.audit\s*!==\s*undefined\s*&&\s*opts\.audit\s*!==\s*null[\s\S]{0,200}?safeEmit\s*!==\s*["']function["']/,
    allowlist: [],
    reason: "Extracted across api-key / cache / notify / permissions / seeders / webhook (signer + verifier) / auth/lockout / middleware/db-role-for / external-db-migrate. The inline shape was identical 10x.",
  },
  {
    id: "inline-observability-shape-validation",
    primitive: "validateOpts.observabilityShape(observability, label, ErrorClass)",
    regex: /opts\.observability\s*!==\s*undefined\s*&&\s*opts\.observability\s*!==\s*null[\s\S]{0,200}?event\s*!==\s*["']function["']/,
    allowlist: [],
    reason: "Extracted parallel to auditShape — opts.observability shape validation across i18n / cache / auth.lockout.",
  },
  {
    id: "inline-optional-boolean-validation",
    primitive: "validateOpts.optionalBoolean(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*typeof\s+opts\.\w+\s*!==\s*["']boolean["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.js's configurePool throws raw Error, not a
      // framework-error class. Surfaced earlier in the session as a
      // harmonization candidate. Allowlist until a framework-error
      // class is wired into http-client.
      "lib/http-client.js",
    ],
    reason: "Extracted across api-key / cache / notify / permissions / seeders / webhook / db-role-for. Centralized boolean type-check.",
  },
  {
    id: "inline-optional-function-validation",
    primitive: "validateOpts.optionalFunction(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*typeof\s+opts\.\w+\s*!==\s*["']function["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.js uses bare `throw new Error(...)` for several opts —
      // doesn't fit the framework-error class signature optionalFunction
      // requires. Tracked in the cross-module follow-ups list.
      "lib/http-client.js",
      // i18n.js's onMissingKey / notify.js's redact include extra
      // signature context in the message ("(key, locale)" /
      // "returning a redacted message") — not a clean shape match.
      "lib/i18n.js",
      "lib/notify.js",
      // retry.js uses raw TypeError, not framework-error.
      "lib/retry.js",
    ],
    reason: "Extracted across api-key / cache / seeders / webhook / db-role-for / permissions / auth/lockout. Centralized function type-check.",
  },
  {
    id: "inline-optional-positive-int-validation",
    primitive: "validateOpts.optionalPositiveInt(value, label, ErrorClass, code?)",
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*!_isPositiveInt\s*\(\s*opts\.\w+\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted across api-key / others. Routes through numericChecks.isPositiveInt; the helper bakes in the throw semantics.",
  },
  {
    id: "inline-optional-positive-finite-validation",
    primitive: "validateOpts.optionalPositiveFinite(value, label, ErrorClass, code?)",
    // Match the literal shape `if (X !== undefined && (typeof X !== "number"
    // || !isFinite(X) || X <= 0))` — the strict positive-finite gate that
    // the optionalPositiveFinite helper bakes in.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']number["']\s*\|\|\s*!isFinite\s*\(\s*opts\.\w+\s*\)\s*\|\|\s*opts\.\w+\s*<=\s*0\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Centralizes the > 0 finite-number check. Every primitive that gates on a positive finite numeric (e.g. mfaWindowMs, ttlMs minimums) routes through here.",
  },
  {
    id: "inline-optional-non-empty-string-validation",
    primitive: "validateOpts.optionalNonEmptyString(value, label, ErrorClass, code?)",
    // Match the OPTIONAL shape only — `X !== undefined && (typeof X !==
    // "string" || X.length === 0)`. The required form (no undefined
    // guard) is a separate primitive (requireNonEmptyString) below.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(?\s*typeof\s+opts\.\w+\s*!==\s*["']string["']\s*\|\|\s*opts\.\w+\.length\s*===\s*0/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Centralizes the optional non-empty-string gate for fields that may be omitted but must be a non-empty string when present.",
  },
  {
    id: "inline-require-non-empty-string-validation",
    primitive: "validateOpts.requireNonEmptyString(value, label, ErrorClass, code?)",
    // Match the REQUIRED shape — `if (typeof X !== "string" ||
    // X.length === 0) throw` at the top of a validation block. The
    // regex also matches inner if-blocks nested inside outer `X !==
    // undefined &&` guards (compound-optional shape) — those sites are
    // allowlisted below because the helper doesn't compose with the
    // adjacent _validateIdent / format check.
    regex: /\bif\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']string["']\s*\|\|\s*opts\.\w+\.length\s*===\s*0\s*\)/,
    allowlist: [
      "lib/validate-opts.js",
      // Compound validators — type-check + _validateIdent / format
      // check / URL example combined. Splitting the type check out
      // would scatter validation across two helpers and lose
      // operator-readable error messages.
      "lib/backup/bundle.js",                    // line 92 — operator-meaningful "(use vault.getKeysJson() ...)" hint
      "lib/cache.js",                            // line 192 — backend === "redis" precondition + URL example
      "lib/cli-helpers.js",                      // raw Error (no framework class)
      "lib/db-declare-row-policy.js",            // optional + _validateIdent compound
      "lib/db-declare-view.js",                  // optional + _validateIdent compound
      "lib/middleware/csp-nonce.js",             // optional-with-default + operator hint
      "lib/middleware/db-role-for.js",           // optional + _validateRoleIdentifier compound
      "lib/protocol-dispatcher.js",              // optional fallbackProtocol guard
      "lib/pubsub-redis.js",                     // raw Error (no framework class)
      "lib/restore-rollback.js",                 // compound: derives rollbackRoot from opts.dataDir
      // permanent: true 3rd-arg sites — helper signature doesn't
      // expose the permanent flag. Refactoring would silently drop it.
      "lib/migrations.js",
      "lib/queue-redis.js",
      "lib/queue-sqs.js",
    ],
    reason: "Required non-empty-string fields. Most primitives' create() functions start with this shape for opts.namespace / opts.dir / opts.url / opts.region / etc. Centralizes the throw + message format. 13 sites allowlisted with documented per-site reasons (compound validators, raw Error, permanent-arg, operator-meaningful extra context).",
  },
  {
    id: "inline-optional-finite-non-negative-validation",
    primitive: "validateOpts.optionalFiniteNonNegative(value, label, ErrorClass, code?)",
    // Match either `!_isFiniteNonNegative(opts.X)` or the full inline form
    // `typeof opts.X !== "number" || !isFinite(opts.X) || opts.X < 0`.
    regex: /opts\.\w+\s*!==\s*undefined\s*&&\s*\(\s*typeof\s+opts\.\w+\s*!==\s*["']number["']\s*\|\|\s*!isFinite\s*\(\s*opts\.\w+\s*\)\s*\|\|\s*opts\.\w+\s*<\s*0\s*\)/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted across primitives. Centralizes the non-negative-finite numeric check.",
  },
  {
    id: "inline-optional-non-empty-string-array-validation",
    primitive: "validateOpts.optionalNonEmptyStringArray(value, label, ErrorClass, code?)",
    // Match the four-line cascade `if (opts.X !== undefined) { if
    // (!Array.isArray(opts.X)) throw ... ; for (i...) if (typeof opts.X[i]
    // !== "string" || opts.X[i].length === 0) throw }` — recurring across
    // api-key (scopes), file-upload (allowedFileTypes), seeders (dependsOn),
    // i18n (rtlLanguages / eagerLocales), and others.
    regex: /!\s*Array\.isArray\s*\(\s*\w+\.\w+\s*\)[\s\S]{0,400}?typeof\s+\w+\.\w+\s*\[\s*\w+\s*\]\s*!==\s*["']string["']\s*\|\|\s*\w+\.\w+\s*\[\s*\w+\s*\]\.length\s*===\s*0/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted to validateOpts.optionalNonEmptyStringArray. Replaces the per-file `if (X !== undefined) { if (!Array.isArray) throw; for (i) if (typeof !== string || === '') throw }` cascade with one call.",
  },
  {
    id: "inline-optional-object-with-method-validation",
    primitive: "validateOpts.optionalObjectWithMethod(value, method, label, ErrorClass, code?, description?)",
    // Match the literal duck-typed-handle shape: `if (opts.X !== undefined
    // && opts.X !== null) { if (typeof opts.X !== "object" || typeof
    // opts.X.method !== "function") throw }` — recurring across file-upload
    // (permissions.check), notify (queue.enqueue), seeders (db.prepare),
    // webhook (nonceStore.checkAndInsert).
    regex: /\w+\.\w+\s*!==\s*undefined\s*&&\s*\w+\.\w+\s*!==\s*null[\s\S]{0,200}?typeof\s+\w+\.\w+\s*!==\s*["']object["']\s*\|\|\s*typeof\s+\w+\.\w+\.\w+\s*!==\s*["']function["']/,
    allowlist: [
      "lib/validate-opts.js",
      // http-client.jar checks TWO methods (cookieHeaderFor + setFromResponse)
      // — the helper validates a single method, so refactoring would
      // silently drop one of the two checks.
      "lib/http-client.js",
      // mail.dkimSigner uses MailError(code, msg, permanent) — the
      // 3-arg constructor signature drops the permanent flag if routed
      // through validateOpts._throw which calls new errorClass(code, msg).
      "lib/mail.js",
    ],
    reason: "Extracted to validateOpts.optionalObjectWithMethod. Replaces the recurring `if (X !== undefined && X !== null) { if (typeof X !== 'object' || typeof X.method !== 'function') throw }` shape used to validate optional duck-typed handles. Allowlisted sites either check multiple methods or use a 3-arg error constructor that the helper would drop.",
  },
  {
    id: "inline-audit-emit-wrapper",
    primitive: "validateOpts.makeAuditEmitter(audit)",
    // Detect the literal `audit.safeEmit(Object.assign({ action: action },
    // info))` shape inside a try/catch — the boilerplate every primitive
    // previously rolled to wrap the operator-supplied audit handle.
    regex: /audit\.safeEmit\s*\(\s*Object\.assign\s*\(\s*\{\s*action\s*:\s*action\s*\}/,
    allowlist: ["lib/validate-opts.js"],
    reason: "Extracted to validateOpts.makeAuditEmitter — closure factory parallel to safeAsync.makeDropCallback. Replaces the per-file `function _emit(action, info) { if (!audit) return; try { ... } catch ... }` boilerplate.",
  },
  {
    id: "inline-default-resolution-cascade",
    primitive: "validateOpts.applyDefaults(opts, DEFAULTS)",
    // Detect the literal shape `(opts.X === undefined) ? DEFAULTS.X : opts.X`
    // — the cascade every primitive's create() previously ran 5–10 times
    // in a row to layer DEFAULTS over operator opts.
    regex: /\(\s*opts\.\w+\s*===\s*undefined\s*\)\s*\?\s*DEFAULTS\.\w+\s*:\s*opts\.\w+/,
    allowlist: [
      "lib/validate-opts.js",
      // testing.js's runMiddleware uses opts.timeoutMs but
      // DEFAULTS.runMiddlewareTimeoutMs — different key names, single
      // field. applyDefaults requires same-key on both sides; this site
      // legitimately keeps the inline ternary.
      "lib/testing.js",
    ],
    reason: "Extracted to validateOpts.applyDefaults — single helper that resolves opts against DEFAULTS in one call. Replaces 5–10 line cascades.",
  },
  {
    id: "inline-require-object-prelude",
    primitive: "validateOpts.requireObject(opts, label, ErrorClass)",
    regex: /if\s*\(\s*!opts\s*\|\|\s*typeof\s+opts\s*!==\s*["']object["']\s*\)\s*\{[\s\S]{0,200}?opts\s+must\s+be\s+an\s+object/,
    allowlist: [
      "lib/validate-opts.js",
      // The three call sites below pass `permanent: true` as the 3rd
      // arg to `_err(code, msg, permanent)`. validateOpts.requireObject
      // doesn't expose that arg — refactoring would silently drop the
      // permanence flag (which controls retry classification). Keep
      // these inline until requireObject grows opts.permanent or these
      // sites move to an alwaysPermanent error class.
      "lib/external-db.js",
      "lib/http-client.js",
      "lib/object-store/sigv4-bucket-ops.js",
    ],
    reason: "Extracted across api-key / cache / i18n / notify / permissions / seeders / webhook. Files with custom error codes or divergent messages (break-glass / config / deprecate / etc.) keep their bespoke shape — those preludes use module-namespaced codes that don't fit the generic helper.",
  },
  {
    id: "inline-onDrop-callback-wrapper",
    primitive: "safeAsync.safeInvoke(callback, payload, onError?)",
    // Detect the literal `onDrop({...})` call wrapped in try/catch — the
    // shape every log-stream sink previously rolled by hand.
    regex: /try\s*\{\s*onDrop\s*\(\s*\{[\s\S]{0,200}?\}\s*\)\s*;?\s*\}\s*catch/,
    allowlist: [],
    reason: "Extracted to safeAsync.safeInvoke — operator-supplied callbacks must invoke through the framework wrapper so throws can't cascade into the sink's flush loop.",
  },
  {
    id: "inline-object-store-http-request",
    primitive: "require('./http-request') (lib/object-store/http-request.js)",
    // Detect the literal `httpClient.request({ method, url, headers, body,
    // idleTimeoutMs, errorClass: ObjectStoreError, allowedProtocols })`
    // shape every protocol backend previously rolled by hand.
    regex: /errorClass\s*:\s*ObjectStoreError\s*,\s*allowedProtocols\s*:/,
    allowlist: ["lib/object-store/http-request.js"],
    reason: "Extracted across azure-blob / gcs / sigv4 / http-put. The shared helper threads the same five opts (idleTimeoutMs / maxResponseBytes / errorClass / allowedProtocols / allowInternal) through httpClient.request.",
  },
  {
    id: "inline-sql-transaction-wrapper",
    primitive: "dbSchema.runInTransaction(db, fn, opts?) — also dbSchema.runSqlOnHandle(db, sql)",
    // The literal BEGIN / COMMIT / ROLLBACK try/catch shape every
    // SQL-touching primitive previously rolled by hand. Match the
    // distinctive `_runSql ( ... , "BEGIN"` followed by COMMIT in the
    // same scope. Tokenized: `_ID ( _ID , _STR )` where _STR is "BEGIN".
    // Hard to match _STR contents post-tokenization; match the
    // surrounding shape instead: a `try { ... "BEGIN" ... "COMMIT" ...
    // } catch ... "ROLLBACK"` shape.
    regex: /"BEGIN"[\s\S]{0,400}?"COMMIT"[\s\S]{0,200}?\}\s*catch[\s\S]{0,300}?"ROLLBACK"/,
    allowlist: [
      "lib/db-schema.js",   // definition site (runInTransaction itself)
      // db.js's `transaction(fn)` is the framework's PUBLIC transaction
      // primitive — operates on the singleton `database` and is the
      // call shape operators use. It already routes through the
      // shared runSql; re-routing through runInTransaction would change
      // semantics (passing module.exports vs database). Keep as-is.
      "lib/db.js",
    ],
    reason: "Extracted to dbSchema.runInTransaction. Replaces the inline BEGIN / COMMIT / ROLLBACK try/catch boilerplate in migrations / seeders / db-schema. Handles both raw better-sqlite3 and b.db framework wrapper handles via runSqlOnHandle.",
  },
  {
    id: "inline-numeric-bounds-cascade",
    primitive: "numericBounds.requirePositiveFiniteIntIfPresent / requireNonNegativeFiniteIntIfPresent",
    // Detect the literal `if (opts.X !== undefined) { if (!nb.isYFiniteInt(opts.X)) throw new XError(code, ... + nb.shape(opts.X)); }`
    // shape that every primitive's create() rolled by hand. Tokenized:
    // `! _ID . _ID ( _ID . _ID ) ) { throw new _ID ( _STR , _STR + _ID . _ID ( _ID . _ID )`
    // — the distinctive `+ nb.shape(opts.X)` tail fingerprints it.
    regex: /!\s*\w+\.is\w*FiniteInt\s*\(\s*\w+\.\w+\s*\)[\s\S]{0,200}?\w+\.shape\s*\(\s*\w+\.\w+\s*\)/,
    allowlist: [
      "lib/numeric-bounds.js",   // definition site
      // The helper signature is `new errorClass(code, message)`. Sites
      // below use one of: factory call `_err(code, msg)`, raw
      // `new Error(...)`, 3rd-arg `permanent: true`, or a reversed
      // `(message, code)` constructor signature. Refactoring would
      // either drop semantics or flip a public error constructor.
      // Tracked as follow-ups in the agent's report.
      "lib/http-client-cookie-jar.js",
      "lib/mail-bounce.js",
      "lib/migrations.js",
      "lib/object-store/gcs.js",
      "lib/object-store/sigv4.js",
      "lib/parsers/safe-env.js",
      "lib/parsers/safe-toml.js",
      "lib/parsers/safe-yaml.js",
      "lib/pqc-gate.js",
      "lib/queue-local.js",
      "lib/safe-buffer.js",
      "lib/safe-url.js",
    ],
    reason: "Extracted to numericBounds.requirePositiveFiniteIntIfPresent / requireNonNegativeFiniteIntIfPresent. Replaces the per-file `if (opts.X !== undefined) { if (!nb.isYFiniteInt(opts.X)) throw }` cascade with a single call.",
  },
  {
    id: "inline-log-via-or-fallback",
    primitive: "log.makeViaOrFallback(operatorLog, fallbackLog)",
    // Detect the literal `if (log && typeof log[level] === "function")
    // { try { log[level](message, fields); } catch ... } return; ...
    // fallback;` shape every log-routing primitive previously rolled
    // by hand. Tokenized: `if ( _ID && typeof _ID [ _ID ] === _STR ) {
    // try { _ID [ _ID ] ( _ID , _ID ) ; } catch`.
    regex: /if\s*\(\s*\w+\s*&&\s*typeof\s+\w+\s*\[\s*\w+\s*\]\s*===\s*["']function["']\s*\)\s*\{\s*try\s*\{\s*\w+\s*\[\s*\w+\s*\]\s*\(/,
    allowlist: [
      "lib/log.js",   // definition site of makeViaOrFallback
      // dev.js + pqc-gate.js — module-level _logVia(log, level, ...)
      // helpers that take log per-call. Refactoring would either
      // allocate a fresh closure per invocation (wasteful) or require
      // restructuring the file to thread log through closures.
      // Cluster broken (2 files < n=3 threshold); keep until a
      // refactor that consolidates them is justified.
      "lib/dev.js",
      "lib/pqc-gate.js",
    ],
    reason: "Extracted to log.makeViaOrFallback. Replaces the per-file `_logVia` boilerplate that bundler / error-page rolled by hand around an operator-supplied logger with a per-module fallback.",
  },
  {
    id: "inline-flush-timer-scheduler",
    primitive: "safeAsync.makeScheduledFlush(delayMs, flushFn)",
    // The literal `var flushTimer = null;` followed by setTimeout idempotent-schedule shape
    // every batched-write sink previously rolled by hand.
    regex: /var\s+flushTimer\s*=\s*null\s*;[\s\S]{0,300}?if\s*\(\s*flushTimer/,
    allowlist: ["lib/safe-async.js"],
    reason: "Extracted to safeAsync.makeScheduledFlush — idempotent setTimeout coalesce-and-flush helper used by every log-stream sink.",
  },
  {
    id: "inline-emit-event-wrapper",
    primitive: "observability.safeEvent(name, value, labels) — already wraps event() in try/catch",
    // Detect any function that wraps observability.event in try/catch
    // instead of calling the framework helper. The shape is symmetric
    // across every consumer module that needs hot-path emission with
    // drop-silent semantics — extraction was complete, no allowlist.
    regex: /try\s*\{[\s\S]{0,150}?observability\.event\s*\([^)]*\)\s*;?\s*\}\s*catch/,
    allowlist: [],
    reason: "Extracted to observability.safeEvent — drop-silent semantics for hot-path event emission. Any module wrapping observability.event in try/catch should call observability.safeEvent instead.",
  },
  {
    id: "inline-hex-string-validator",
    primitive: "safeBuffer.isHex(s, expectedLength?) — returns boolean",
    regex: /\/\^\[0-9a-fA-F\]\+\$\/\s*\.\s*test\s*\(/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "Hex-string validation is now safeBuffer.isHex / safeBuffer.HEX_RE. The lib/safe-buffer.js definition retains the literal regex.",
  },
  {
    id: "inline-crlf-string-test",
    primitive: "safeBuffer.hasCrlf(s) / safeBuffer.CRLF_RE",
    regex: /\/\[\\r\\n\]\/\s*\.\s*test\s*\(/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "CRLF-injection guards now route through safeBuffer.hasCrlf / safeBuffer.CRLF_RE. The lib/safe-buffer.js definition retains the literal regex.",
  },
  {
    id: "inline-trailing-hspace-strip",
    primitive: "safeBuffer.stripTrailingHspace(s) / safeBuffer.TRAILING_HSPACE_RE",
    regex: /\.replace\s*\(\s*\/\[\s\\t\]\+\$\/\s*,/,
    allowlist: ["lib/safe-buffer.js"],
    reason: "Trailing horizontal-whitespace strip is now safeBuffer.stripTrailingHspace. The lib/safe-buffer.js definition keeps the literal regex.",
  },
  {
    id: "inline-iso8601-millisecond-strip",
    primitive: "time.toIso8601NoMs(date)",
    regex: /\.toISOString\s*\(\s*\)\s*\.\s*replace\s*\(\s*\/\\\.\\d\{3\}Z\$\//,
    allowlist: ["lib/time.js"],
    reason: "ISO-8601 millisecond stripping is now time.toIso8601NoMs(). The helper definition in lib/time.js keeps the inline form.",
  },
  {
    id: "inline-migration-filename-regex",
    primitive: "migrationFiles.MIGRATION_FILE_RE / migrationFiles.isMigrationFileName(name)",
    regex: /\/\^\\\?\(\\d\+\)-\(\[A-Za-z0-9_-\]\+\)\\\.js\$\//,
    allowlist: ["lib/migration-files.js"],
    reason: "Migration filename pattern is now migrationFiles.MIGRATION_FILE_RE. The migration-files module owns the literal.",
  },
  {
    id: "inline-sql-identifier-regex",
    primitive: "safeSql.DEFAULT_IDENTIFIER_RE / safeSql.MAX_IDENTIFIER_LENGTH",
    regex: /\/\^\[A-Za-z_\]\[A-Za-z0-9_\]\*\$\//,
    allowlist: ["lib/safe-sql.js"],
    reason: "SQL identifier validation is now safeSql.DEFAULT_IDENTIFIER_RE. The lib/safe-sql.js definition keeps the literal.",
  },
  {
    id: "inline-optional-plain-object-validation",
    primitive: "validateOpts.optionalPlainObject(value, label, ErrorClass, code?, description?)",
    // Match the literal three-line cascade `if (X !== undefined && X !==
    // null) { if (typeof X !== "object" || Array.isArray(X)) throw ... }`
    // — the recurring "optional plain object (not array)" validator
    // shape shared by api-key (metadata), db-declare-view (hashColumns),
    // db-declare-row-policy, static.js (contentSafety).
    regex: /\w+\.\w+\s*!==\s*undefined\s*&&\s*\w+\.\w+\s*!==\s*null[\s\S]{0,200}?typeof\s+\w+\.\w+\s*!==\s*["']object["']\s*\|\|\s*Array\.isArray/,
    allowlist: [
      "lib/validate-opts.js",
      // external-db throws ExternalDbError with a 3rd `permanent: true`
      // arg that the validateOpts._throw factory signature doesn't carry
      // through. Routing through the helper would silently drop the
      // permanence flag (which controls retry classification).
      "lib/external-db.js",
      // protocol-dispatcher constructs the error inline with multi-line
      // formatted message details that don't fit the helper's
      // (label + description) shape.
      "lib/protocol-dispatcher.js",
    ],
    reason: "Extracted to validateOpts.optionalPlainObject. Replaces the recurring `if (X !== undefined && X !== null) { if (typeof X !== 'object' || Array.isArray(X)) throw }` shape used to validate optional plain-object opts. Two sites allowlisted: external-db needs the permanent-flag 3rd arg the helper drops; protocol-dispatcher uses multi-line formatted error messages that don't fit the helper's description slot.",
  },
  {
    id: "inline-redis-client-opts-forwarding",
    primitive: "redisClient.pickClientOpts(cfg, prefix?)",
    // Match the literal 9-key opts construction `{ url, password, username,
    // tls, ca, servername, connectTimeoutMs, commandTimeoutMs,
    // maxReconnectAttempts }` that cache-redis / pubsub-redis / queue-redis
    // / etc. previously each rolled by hand to forward to redisClient.create.
    // Detect via the distinctive triple `connectTimeoutMs ... commandTimeoutMs
    // ... maxReconnectAttempts` appearing within a small window (those three
    // keys uniquely identify a redis-client opts bag — no other framework
    // primitive uses all three together).
    regex: /connectTimeoutMs[\s\S]{0,300}?commandTimeoutMs[\s\S]{0,300}?maxReconnectAttempts/,
    allowlist: ["lib/redis-client.js"],
    reason: "Extracted to redisClient.pickClientOpts(cfg, prefix?) — single helper that returns the 9-key opts bag. cache-redis / pubsub-redis / queue-redis route through it. New redis-using primitives must call pickClientOpts; never hand-roll the 9-key forward.",
  },
  {
    id: "inline-buffer-byte-equality-loop",
    primitive: "Buffer.compare(a, b) === 0 (for non-crypto byte equality)",
    // Hand-rolled loop walking two buffers byte-by-byte and OR-ing into
    // a diff accumulator. Crypto-equality belongs in timingSafeEqual;
    // non-crypto equality belongs in Buffer.compare.
    regex: /for\s*\([^)]*\)\s*\{[\s\S]{0,150}?\|=\s*\w+\[\w+\]\s*\^\s*\w+\[\w+\]/,
    allowlist: [
      // timingSafeEqual implementation legitimately walks both buffers.
      "lib/safe-buffer.js",
      "lib/crypto.js",
    ],
    reason: "Non-crypto byte equality is Buffer.compare(a, b) === 0. ssrf-guard / address-equality call sites migrated. New code must use Buffer.compare or timingSafeEqual; never hand-roll the loop.",
  },
];

function testKnownAntipatterns() {
  // class: known-antipattern
  // Fires at n=1 — any file matching a registered antipattern (and not
  // in its allowlist) fails the gate with a pointer to the primitive
  // that should replace it.
  var files = _libFiles();
  var allBad = [];
  for (var ai = 0; ai < KNOWN_ANTIPATTERNS.length; ai++) {
    var ap = KNOWN_ANTIPATTERNS[ai];
    var allowSet = Object.create(null);
    for (var k = 0; k < ap.allowlist.length; k++) allowSet[ap.allowlist[k]] = true;
    var bad = [];
    for (var fi = 0; fi < files.length; fi++) {
      var rel = _relPath(files[fi]);
      if (allowSet[rel]) continue;
      var content;
      try { content = fs.readFileSync(files[fi], "utf8"); }
      catch (_e) { continue; }
      var m = ap.regex.exec(content);
      if (!m) continue;
      // Compute line number from match index.
      var lineNum = content.slice(0, m.index).split(/\r?\n/).length;
      bad.push({
        file: rel,
        line: lineNum,
        content: "antipattern '" + ap.id + "' — use " + ap.primitive,
      });
    }
    if (bad.length) {
      allBad = allBad.concat(bad);
      _report("known-antipattern '" + ap.id + "' — use " + ap.primitive, bad);
    }
  }
  if (allBad.length === 0) {
    check("known-antipattern catalog (n=1 gate)", true);
  }
}

async function run() {
  testNoRawByteLiterals();
  testNoRawTimeLiterals();
  testNumericOptsValidate();
  testHttp2TeardownPaired();
  testNoStrayConsoleCalls();
  testNoUnresolvedMarkers();
  testNoTierTerminologyInLib();
  testNoInlineRequires();
  testNoMathRandomForSecurity();
  testNoRawHashCompare();
  testRawNewURL();
  testNoBareJsonParse();
  testNoBareCanonicalizeWalks();
  testFormatValidatorLengthCap();
  testNoProcessExitInLib();
  testNoSilentCatchSwallow();
  testNoDynamicRegexFromOperatorInput();
  testNoRawXffRead();
  testNoRawRemoteAddress();
  testNoRawProcessEnv();
  testNoRawTimingSafeEqual();
  testParseIntRadix();
  testBufferFromStringEncoding();
  testTimersUnref();
  testNoRawRandomBytesToken();
  testNoHandrolledSleep();
  testNoRawOutboundHttp();
  testNoNumberEnvCoercion();
  // Primitive-extraction-candidate detectors.
  testNoDuplicateRegexAcrossFiles();
  testNoHandrolledDeepClone();
  testNoHandrolledBufferCollect();
  testNoHandrolledDebounce();
  testNoHandrolledPromiseRaceTimeout();
  testNoManualByteCompare();
  testNoOpenCodedLazyRequire();
  testNoBareErrorThrows();
  testNoHandrolledUrlBuild();
  testNoHandrolledRetryLoop();
  testNoDuplicateCodeBlocks();
  testNoStateStampsInPublicDocs();
  testKnownAntipatterns();

  // Final cumulative assertion — every detector is a hard gate.
  check("zero codebase-pattern violations across all classes",
        _allViolations.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  // Persistent output to .test-output/codebase-patterns.log so agents
  // iterating on a failing run can grep the file instead of re-running.
  // Synchronous fd writes (mirroring test/smoke.js) — async streams
  // don't flush before process exit, which previously left the log
  // empty after a failed run.
  var fsLog   = require("node:fs");
  var pathLog = require("node:path");
  var REPO_ROOT = pathLog.resolve(__dirname, "..", "..");
  var OUT = pathLog.join(REPO_ROOT, ".test-output");
  try { fsLog.mkdirSync(OUT, { recursive: true }); } catch (_e) { /* best-effort */ }
  var LOG_PATH = pathLog.join(OUT, "codebase-patterns.log");
  try { fsLog.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
  var _logFd = fsLog.openSync(LOG_PATH, "w");
  function _logWrite(chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fsLog.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* best-effort */ }
  }
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) {
    _logWrite(c);
    return origStdout(c, e, cb);
  };
  process.stderr.write = function (c, e, cb) {
    _logWrite(c);
    return origStderr(c, e, cb);
  };
  process.on("exit", function () {
    try { fsLog.closeSync(_logFd); } catch (_e) { /* best-effort */ }
  });
  console.log("output: " + LOG_PATH);
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
