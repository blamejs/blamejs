// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * _codebase-shingle — shared shingle-scan helpers extracted from
 * test/layer-0-primitives/codebase-patterns.test.js so the heavy
 * tokenize + cross-file shingle scan can run inside worker_threads.
 *
 * The main `testNoDuplicateCodeBlocks` detector shards the corpus
 * across N workers. Each worker calls `prepareShard(absFiles, opts)`
 * once to tokenize and filter its shard, then answers a series of
 * `scanRound(prepared, {pass, size})` requests — one fingerprint map
 * per (pass, size) combination. The main thread merges the shards for
 * a combination, folds it into the cluster table, and releases it
 * before asking for the next one.
 *
 * KEEP IN SYNC: the helpers below are the verbatim copies of the
 * functions previously inlined in codebase-patterns.test.js. Do not
 * fork the logic — change once here and the worker + the test stay
 * consistent.
 */

var fs   = require("fs");
var path = require("path");

// The words a normalized line keeps verbatim. Everything else that reads as an
// identifier becomes `_ID`, so two functions differing only in variable or file
// names produce the same fingerprint. The Node module globals are here so a
// require block reads as boilerplate to `isBoilerplate` rather than as a
// duplicate.
var JS_KEYWORDS = new Set([
  "var", "let", "const", "function", "return", "if", "else", "for",
  "while", "do", "switch", "case", "default", "break", "continue",
  "try", "catch", "finally", "throw", "new", "this", "null", "undefined",
  "true", "false", "typeof", "instanceof", "in", "of", "delete", "void",
  "async", "await", "class", "extends", "super", "import", "export",
  "from", "as", "with", "yield", "static",
  "require", "module", "exports", "Buffer", "process", "console",
  "Promise", "Object", "Array", "String", "Number", "Boolean", "Date",
  "RegExp", "Error", "Math", "JSON", "Symbol", "Map", "Set", "WeakMap",
  "WeakSet", "Reflect", "Proxy",
]);

function normalizeJsLine(line) {
  line = line.replace(/\/\/.*$/, "");
  line = line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "_STR");
  line = line.replace(/(^|[=(,?:[;!&|]|\breturn\s|\bthrow\s|=>\s*)\/((?:\\.|[^/\\\n])+)\/[gimsuy]*/g,
                      "$1_RE");
  line = line.replace(/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|0x[0-9a-fA-F]+/g, "_NUM");
  line = line.replace(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g, function (name) {
    if (name === "_STR" || name === "_NUM" || name === "_RE") return name;
    return JS_KEYWORDS.has(name) ? name : "_ID";
  });
  line = line.replace(/([.(){}[\];,:?!&|^~<>=+\-*/%@])/g, " $1 ");
  line = line.replace(/\s+/g, " ").trim();
  return line;
}

function tokenizeFile(absPath, repoRoot) {
  var rel;
  try { rel = path.relative(repoRoot, absPath).replace(/\\/g, "/"); }
  catch (_e) { rel = absPath; }
  var content;
  try { content = fs.readFileSync(absPath, "utf8"); }
  catch (_e) { return null; }
  var lines = content.split(/\r?\n/);
  var tokens = [];
  for (var li = 0; li < lines.length; li++) {
    var rawLine = lines[li];
    if (/^\s*(\/\/|\*|\/\*)/.test(rawLine)) continue;
    var norm = normalizeJsLine(rawLine);
    if (norm.length === 0) continue;
    var lineToks = norm.split(/\s+/).filter(function (t) { return t.length > 0; });
    for (var ti = 0; ti < lineToks.length; ti++) {
      tokens.push({ tok: lineToks[ti], line: li + 1 });
    }
  }
  return { rel: rel, tokens: tokens };
}

function isBoilerplate(slice) {
  var toks = slice.map(function (t) { return t.tok; });
  var joined = toks.join(" ");
  var requireCallSeq = /\brequire\s+\(\s+_STR\s+\)/g;
  var requireCalls = (joined.match(requireCallSeq) || []).length;
  if (requireCalls >= 2) return true;
  if (requireCalls === 1 && slice.length <= 10) return true;
  if (/_ID\s+=\s+_ID\s+\(\s+function\s+\(\s+\)\s+\{\s+return\s+require\s+\(\s+_STR\s+\)/.test(joined)) return true;
  if (/_ID\s+\(\s+\)\s+\.\s+_ID\s+\(\s+_ID\s+,\s+_ID\s+,\s+_ID\s+\|\s+\|\s+\{\s+\}\s+\)/.test(joined)) return true;
  if (/!\s+_ID\s+\)\s+return\s+;\s+try\s+\{\s+_ID\s+\.\s+_ID\s+\(/.test(joined)) return true;
  var unpackSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+;/g;
  var unpacks = (joined.match(unpackSeq) || []).length;
  if (unpacks >= 2) return true;
  var strCommaSeq = /_STR\s+,\s+_STR\s+,\s+_STR\s+,\s+_STR/g;
  if (strCommaSeq.test(joined)) return true;
  if (/_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+\/\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)/.test(joined)) return true;
  if (/_ID\s+\.\s+_ID\s+=\s+=\s+=\s+true\s+\|\s+\|\s+typeof\s+_ID\s+\.\s+_ID\s+=\s+=\s+=\s+_STR/.test(joined)) return true;
  if (/if\s+\(\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+undefined\s+&\s+&\s+_ID\s+\.\s+_ID\s+!\s+=\s+=\s+null\s+\)/.test(joined)) return true;
  var validateChainSeq = /_ID\s+\.\s+_ID\s+\(\s+_ID\s+\.\s+_ID\s+,\s+_STR\s+,\s+_ID\s+\)\s+;/g;
  var validateChainCount = (joined.match(validateChainSeq) || []).length;
  if (validateChainCount >= 2) return true;
  if (/\bclass\s+_ID\s+extends\s+_ID/.test(joined)) return true;
  if (/\bclass\s+T\s+extends\s+T/.test(joined)) return true;
  if (/module\s+\.\s+exports\s+=\s+\{/.test(joined)) return true;
  var kvPairs = (joined.match(/_ID\s+:\s+_ID\s+,/g) || []).length;
  if (kvPairs >= 4) return true;
  if (/\bdefineClass\s+\(\s+_STR/.test(joined)) return true;
  var constantDeclSeq = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\.\s+_ID\s+\(\s+_NUM\s+\)\s+;/g;
  var constantDecls = (joined.match(constantDeclSeq) || []).length;
  if (constantDecls >= 2) return true;
  var constantDeclSeq2 = /var\s+_ID\s+=\s+_ID\s+\.\s+_ID\s+\(\s+(?:_NUM|_STR)\s*[),]/g;
  var constantDecls2 = (joined.match(constantDeclSeq2) || []).length;
  if (constantDecls2 >= 3) return true;
  var declTokens = toks.filter(function (t) {
    return t === "=" || t === ";" || t === "," || t === ":" ||
           t === "_STR" || t === "_NUM" || t === "var" || t === "const";
  }).length;
  if (declTokens >= Math.floor(slice.length * 0.55)) return true;
  var rangeCheckSeq = /_ID\s+>\s+=\s+_NUM\s+&\s+&\s+_ID\s+<\s+=\s+_NUM/g;
  var rangeChecks = (joined.match(rangeCheckSeq) || []).length;
  if (rangeChecks >= 2) return true;
  if (/for\s+\(\s+var\s+_ID\s+=\s+_NUM\s+;\s+_ID\s+<\s+_ID\s+\.\s+_ID\s+;\s+_ID\s+\+\s+\+\s+\)/.test(joined)) return true;
  var throwTypeofSeq = /if\s+\(\s+typeof\s+_ID[\s\S]{0,40}?\)\s+\{\s+throw\s+new\s+_ID\s+\(\s+_STR\s+,\s+_STR\s+\)\s+;\s+\}/g;
  var throwTypeofs = (joined.match(throwTypeofSeq) || []).length;
  if (throwTypeofs >= 2) return true;
  return false;
}

// Same fingerprints as the inline versions. (Hash-based variant
// tested in v0.8.26 surfaced previously-grouped duplicates as
// distinct clusters — the join-on-space form preserves the cluster
// identity the existing KNOWN_CLUSTERS allowlist depends on.)
function sliceFingerprintExact(slice) {
  return slice.map(function (t) { return t.tok; }).join(" ");
}
function sliceFingerprintSkeleton(slice) {
  return slice.map(function (t) {
    var k = t.tok;
    if (/^[A-Za-z_]/.test(k)) return "T";
    return k;
  }).join(" ");
}

var DEFAULT_SHINGLE_SIZES = [60, 50, 40, 30, 22, 16, 12, 8];

/**
 * prepareShard(absFiles, opts) — tokenize the assigned files ONCE and
 * record, per (file, size, offset), whether the shingle starting there
 * clears the cheap filters (distinct-token floor, then boilerplate).
 *
 * Returns { files: [{ rel, tokens, keep: { "<size>": Uint8Array } }] },
 * where `keep[size][offset]` is 1 for a shingle that survives.
 *
 * The verdict is what costs: `isBoilerplate` runs a couple of dozen
 * regexes over the joined slice. Deciding it once and consulting a byte
 * per offset lets both fingerprint passes reuse the answer instead of
 * re-deriving it, which is what makes scanning one combination at a
 * time affordable.
 */
function prepareShard(absFiles, opts) {
  opts = opts || {};
  var repoRoot = opts.repoRoot;
  var shingleSizes = opts.shingleSizes || DEFAULT_SHINGLE_SIZES;
  var minDistinctTokens = opts.minDistinctTokens || 5;

  var out = { files: [] };
  for (var fi = 0; fi < absFiles.length; fi += 1) {
    var entry = tokenizeFile(absFiles[fi], repoRoot);
    if (!entry) continue;
    var tokens = entry.tokens;
    var keep = {};
    for (var si = 0; si < shingleSizes.length; si += 1) {
      var n = shingleSizes[si];
      if (tokens.length < n) { keep[n] = new Uint8Array(0); continue; }
      var flags = new Uint8Array(tokens.length - n + 1);
      for (var ti = 0; ti + n <= tokens.length; ti += 1) {
        var slice = tokens.slice(ti, ti + n);
        var distinctMap = {};
        for (var di = 0; di < slice.length; di += 1) distinctMap[slice[di].tok] = true;
        if (Object.keys(distinctMap).length < minDistinctTokens) continue;
        if (isBoilerplate(slice)) continue;
        flags[ti] = 1;
      }
      keep[n] = flags;
    }
    out.files.push({ rel: entry.rel, tokens: tokens, keep: keep });
  }
  return out;
}

/**
 * scanRound(prepared, opts) — fingerprint ONE (pass, size) combination
 * across a prepared shard. `opts.pass` is "exact" or "skeleton";
 * `opts.size` is one of the prepared shingle sizes. Returns
 * `{ fp -> [{file, line, endLine}] }` for that combination alone.
 *
 * One combination at a time is the point. Building all sixteen together
 * meant retaining every distinct fingerprint STRING in the corpus — on
 * the order of eleven million of them, several GB — even though a
 * fingerprint seen in a single file can never reach the two-file floor
 * the cluster aggregation applies. Emitting one combination lets the
 * caller fold it into the cluster table and drop it, so the peak is the
 * largest single combination instead of the sum of all of them.
 *
 * Files are walked in prepared order with offsets ascending, so a
 * fingerprint's site list arrives in the order the all-at-once scan
 * produced. Cluster identity depends on that ordering.
 */
function scanRound(prepared, opts) {
  opts = opts || {};
  var size = opts.size;
  var fpFn = opts.pass === "skeleton" ? sliceFingerprintSkeleton : sliceFingerprintExact;
  var bucket = {};
  var files = prepared.files;
  for (var fi = 0; fi < files.length; fi += 1) {
    var f = files[fi];
    var flags = f.keep[size];
    if (!flags || flags.length === 0) continue;
    var tokens = f.tokens;
    for (var ti = 0; ti < flags.length; ti += 1) {
      if (!flags[ti]) continue;
      var slice = tokens.slice(ti, ti + size);
      var fp = fpFn(slice);
      if (!bucket[fp]) bucket[fp] = [];
      bucket[fp].push({
        file:    f.rel,
        line:    slice[0].line,
        endLine: slice[slice.length - 1].line,
      });
    }
  }
  return bucket;
}

module.exports = {
  JS_KEYWORDS:              JS_KEYWORDS,
  DEFAULT_SHINGLE_SIZES:    DEFAULT_SHINGLE_SIZES,
  normalizeJsLine:          normalizeJsLine,
  tokenizeFile:             tokenizeFile,
  isBoilerplate:            isBoilerplate,
  sliceFingerprintExact:    sliceFingerprintExact,
  sliceFingerprintSkeleton: sliceFingerprintSkeleton,
  prepareShard:             prepareShard,
  scanRound:                scanRound,
};
