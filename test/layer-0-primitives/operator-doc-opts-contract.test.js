// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every option a primitive ACCEPTS is one its block documents.
 *
 * A primitive states its option set twice: the list it accepts, which is the
 * array handed to `validateOpts(opts, [...], label)`, and the list it
 * documents, which is its `@opts` section. Nothing compared them, so an option
 * could be accepted, validated with a throw, and discoverable nowhere:
 * `dkimRequireMode` decided which DKIM signature satisfies `requireDkim` on
 * `b.mail.server.submission.create` and an operator could not learn it existed.
 * That one was found by accident. This is the mechanical check.
 *
 * The comparison is per primitive, and getting the body window right is the
 * whole instrument. A first version ended a function body at the first closing
 * brace in column zero, which in this codebase is the end of the enclosing
 * `create()` factory rather than the end of the primitive, so it attributed
 * every later allowlist in the factory to an earlier block: it credited
 * `b.auth.oauth.parseCallback` with eight options while that function calls no
 * `validateOpts` at all, and reported 140 names across 37 blocks where there
 * were 33 across 17. A `validateOpts` on a NESTED object counts for nothing
 * here either, since `lib/auth/oauth.js` validates a `signedRequestObject`
 * sub-option and `lib/openapi.js` validates its builder middleware's own
 * options; only an allowlist on the function's own options parameter is this
 * primitive's contract.
 *
 * Which function a block describes cannot be settled by name or by position
 * alone. `b.middleware.cors` is implemented by `function create(opts)`, so
 * requiring the name misses it; that same file declares something called
 * `cors` elsewhere, so preferring the name finds the wrong function. Both
 * candidates are tried and the one that validates its own options is kept,
 * which is the thing being measured.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var ROOT = nodePath.join(__dirname, "..", "..");
var LIB = nodePath.join(ROOT, "lib");

// An injection point for tests. Publishing one in an `@opts` block would make
// it operator surface, which is the opposite of what it is for. The underscore
// prefix is the convention and carries itself; a seam that does not wear one is
// listed by name with what it injects, so the exemption is a decision rather
// than a pattern nobody revisits.
var TEST_SEAMS = Object.freeze({
  "b.mail.send.deliver.create": Object.freeze({
    transportFactory: "builds the SMTP transport, so a test can answer without a socket",
  }),
  "b.middleware.rateLimit": Object.freeze({
    clock: "reads the current time, so a test can advance a window without waiting",
  }),
});

var BLOCK_RE = /\/\*\*[\s\S]*?\*\//g;
var ANY_DECL = new RegExp(
  "(?:async\\s+)?function\\s+[A-Za-z_$][\\w$]*\\s*\\(([^)]*)\\)" +
  "|\\b[A-Za-z_$][\\w$]*\\s*:\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)" +
  "|\\b[A-Za-z_$][\\w$]*\\s*=\\s*(?:async\\s+)?(?:function\\s*)?\\(([^)]*)\\)\\s*=>", "g");

function _libFiles(dir, out) {
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = nodePath.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== "vendor") _libFiles(p, out); return; }
    if (e.name.endsWith(".js")) out.push(p);
  });
  return out;
}

// Length-preserving, so an index into the masked text is an index into the
// source and a brace inside a string or a comment cannot skew a scan.
function _mask(text) {
  var out = text.split("");
  var i = 0;
  while (i < out.length) {
    var ch = out[i];
    if (ch === "/" && out[i + 1] === "/") {
      var a = i;
      while (a < out.length && out[a] !== "\n") { out[a] = " "; a += 1; }
      i = a; continue;
    }
    if (ch === "/" && out[i + 1] === "*") {
      var bq = i + 2;
      while (bq < out.length && !(out[bq] === "*" && out[bq + 1] === "/")) bq += 1;
      var stop = Math.min(bq + 2, out.length);
      for (var k = i; k < stop; k += 1) { if (out[k] !== "\n") out[k] = " "; }
      i = stop; continue;
    }
    if (ch !== "\"" && ch !== "'" && ch !== "`") { i += 1; continue; }
    var q = ch;
    var j = i + 1;
    while (j < out.length) {
      if (out[j] === "\\") { j += 2; continue; }
      if (out[j] === q) break;
      if (q !== "`" && out[j] === "\n") break;
      if (out[j] !== "\n") out[j] = "x";
      j += 1;
    }
    i = j + 1;
  }
  return out.join("");
}

function _spanFrom(masked, at, open, close) {
  var start = masked.indexOf(open, at);
  if (start === -1) return null;
  var depth = 0;
  for (var i = start; i < masked.length; i += 1) {
    if (masked[i] === open) depth += 1;
    else if (masked[i] === close) { depth -= 1; if (depth === 0) return { start: start, end: i }; }
  }
  return null;
}

function _bracedFrom(masked, at) { return _spanFrom(masked, at, "{", "}"); }

// Every spelling of the shared validator that declares a key allowlist, and
// where the keys sit. Reading only the first two left 58 of the 413 call sites
// in lib/ invisible, so the gate reported clean over them: `checkOrThrow` is
// the same key check raising the caller's error class, and `shape` refuses a
// key outside its schema, which makes the schema's own field names its
// allowlist. `applyDefaults` is deliberately absent: it drops an unknown key
// instead of refusing it, so it declares defaults rather than a contract.
var ALLOWLIST_CALLS = [
  { call: "validateOpts",                arg: "array"  },
  { call: "validateOpts\\.check",        arg: "array"  },
  { call: "validateOpts\\.checkOrThrow", arg: "array"  },
  { call: "validateOpts\\.shape",        arg: "object" },
];

// The top-level argument spans of the call whose `(` is at openParen, so an
// argument can be read by POSITION. `validateOpts.shape` takes its extra
// accepted keys as `allow` on a SIXTH argument, and reading only the schema
// left those keys invisible: `b.ntpCheck.bootCheck` forwards three through
// `BOOT_CHECK_FORWARDED` and `b.static.create` two inline.
function _argSpans(masked, openParen) {
  var out = [];
  var depth = 0;
  var start = openParen + 1;
  for (var i = openParen; i < masked.length; i += 1) {
    var c = masked[i];
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c === ")" || c === "]" || c === "}") {
      depth -= 1;
      if (depth === 0) { out.push({ start: start, end: i - 1 }); return out; }
      continue;
    }
    if (c === "," && depth === 1) { out.push({ start: start, end: i - 1 }); start = i + 1; }
  }
  return out;
}

function _trimmed(masked, span) {
  var s = span.start;
  var e = span.end;
  while (s <= e && /\s/.test(masked[s])) s += 1;
  while (e >= s && /\s/.test(masked[e])) e -= 1;
  return e < s ? null : { start: s, end: e };
}

// A schema object's own field names: an identifier or quoted name followed by
// `:` at depth 1 whose preceding non-space character is `{` or `,`. That last
// condition is what keeps the colon of a ternary inside a value from reading as
// a field name.
function _schemaFields(masked, src, span) {
  var names = Object.create(null);
  var depth = 0;
  for (var i = span.start; i <= span.end; i += 1) {
    var c = masked[i];
    if (c === "{" || c === "[" || c === "(") { depth += 1; continue; }
    if (c === "}" || c === "]" || c === ")") { depth -= 1; continue; }
    if (c !== ":" || depth !== 1) continue;
    var j = i - 1;
    while (j > span.start && /\s/.test(masked[j])) j -= 1;
    var end = j + 1;
    var name;
    if (masked[j] === '"' || masked[j] === "'") {
      var q = masked[j];
      var k = j - 1;
      while (k > span.start && masked[k] !== q) k -= 1;
      name = src.slice(k + 1, j);
      // BEFORE the opening quote, so the delimiter check below reads the `{` or
      // `,` that precedes the field rather than the quote itself.
      j = k - 1;
    } else {
      while (j >= span.start && /[A-Za-z0-9_$]/.test(masked[j])) j -= 1;
      name = src.slice(j + 1, end);
    }
    var before = j;
    while (before > span.start && /\s/.test(masked[before])) before -= 1;
    if (masked[before] !== "{" && masked[before] !== ",") continue;
    if (/^[A-Za-z_$][\w$]*$/.test(name)) names[name] = true;
  }
  return names;
}

// The functions declared INSIDE this body. A factory's primitives are not the
// factory's own code, and their allowlists are not its allowlist.
function _nestedSpans(masked, body) {
  var spans = [];
  var re = /(?:\b(?:async\s+)?function\b|=>)/g;
  re.lastIndex = body.start + 1;
  var m;
  while ((m = re.exec(masked)) !== null && m.index < body.end) {
    var bd = _bracedFrom(masked, m.index);
    if (!bd || bd.end > body.end) continue;
    if (spans.length && bd.start <= spans[spans.length - 1].end) continue;
    spans.push(bd);
    re.lastIndex = bd.end;
  }
  return spans;
}

function _candidates(masked, from, name) {
  var out = [];
  ANY_DECL.lastIndex = from;
  var a = ANY_DECL.exec(masked);
  if (a) out.push({ index: a.index, params: a[1] || a[2] || a[3] || "" });
  [
    new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\(([^)]*)\\)"),
    new RegExp("\\b" + name + "\\s*:\\s*(?:async\\s+)?function\\s*\\(([^)]*)\\)"),
    new RegExp("\\b" + name + "\\s*=\\s*(?:async\\s+)?(?:function\\s*)?\\(([^)]*)\\)\\s*=>"),
  ].forEach(function (re) {
    var m = re.exec(masked);
    if (!m) return;
    if (out.some(function (c) { return c.index === m.index; })) return;
    out.push({ index: m.index, params: m[1] || "" });
  });
  return out;
}

function _documentedNames(blk, optsAt) {
  var text = blk.slice(optsAt);
  var stopAt = text.search(/@(?:example|exampleFile|section|intro|card)\b/);
  if (stopAt !== -1) text = text.slice(0, stopAt);
  var names = {};
  (text.match(/[A-Za-z_$][\w$]*\??\s*:/g) || []).forEach(function (t) {
    names[t.replace(/\??\s*:$/, "")] = true;
  });
  return names;
}

function collect() {
  var rows = [];
  var measurable = 0;
  var notMeasurable = 0;
  var withOpts = 0;
  var unresolved = [];

  _libFiles(LIB, []).forEach(function (file) {
    var src = nodeFs.readFileSync(file, "utf8");
    var rel = nodePath.relative(ROOT, file).replace(/\\/g, "/");
    var r = _analyze(src, rel);
    rows = rows.concat(r.rows);
    measurable += r.measurable;
    notMeasurable += r.notMeasurable;
    withOpts += r.withOpts;
    unresolved = unresolved.concat(r.unresolved);
  });
  return { rows: rows, measurable: measurable, notMeasurable: notMeasurable,
           withOpts: withOpts, unresolved: unresolved };
}

// The keys one function's own `validateOpts` calls accept. Two spellings reach
// the same validator, and reading only the first was a blind spot of the same
// kind as skipping a block with no `@opts` section: an allowlist the pattern
// could not see left the block counted as unmeasurable, which reads as a clean
// verdict rather than as a gap. `b.compliance.aiAct.gpai.adherenceForm`
// validates against DECLARE_ALLOWED_KEYS and went unmeasured while accepting
// `modalities`, `privateKeyPem`, `serialNumber` and `audit` undocumented.
//
// An identifier whose array literal is not in the file is pushed to
// `unresolved` instead of being passed over, so it fails the run by name.
// Scans the masked source by position rather than a body string, because the
// `shape` schemas carry function values and the nested-function stripping that
// keeps a factory's primitives out would cut them in half.
//
// The \b on each call form keeps a local helper out. Seven modules declare
// their own `_validateOpts`, and `deprecate.js` calls it as
// `_validateOpts(opts, fnName)` where the second argument is a label, not an
// allowlist. Without the boundary that reads as the shared validator handed an
// unresolvable array, which would fail the run over a shape that is not an
// allowlist at all.
function _acceptedNames(src, masked, body, spans, optsParam, rel, prim, unresolved) {
  var accepted = Object.create(null);
  function inNested(idx) {
    for (var i = 0; i < spans.length; i += 1) {
      if (idx > spans[i].start && idx < spans[i].end) return true;
    }
    return false;
  }
  function take(list) {
    (list.match(/"([^"]+)"|'([^']+)'/g) || []).forEach(function (q) {
      accepted[q.slice(1, -1)] = true;
    });
  }
  function takeFields(span) {
    Object.keys(_schemaFields(masked, src, span)).forEach(function (k) { accepted[k] = true; });
  }
  // An array of key names, written inline or bound to a module-level name. The
  // span may be a whole argument or the tail after an `allow:`, so both the
  // array and the identifier are delimited here rather than assumed to end
  // where the span does.
  function takeKeyList(span, where) {
    var t = _trimmed(masked, span);
    if (!t) return;
    if (masked[t.start] === "[") {
      var arr = _spanFrom(masked, t.start, "[", "]");
      if (!arr || arr.end > t.end) return;
      take(src.slice(arr.start, arr.end + 1));
      return;
    }
    var lead = /^[A-Za-z_$][\w$]*/.exec(src.slice(t.start, t.end + 1));
    if (!lead) return;
    var name = lead[0];
    var d = new RegExp("(?:var|let|const)\\s+" + name +
      "\\s*=\\s*(?:Object\\.freeze\\s*\\()?\\[([^\\]]*)\\]").exec(src);
    if (!d) { unresolved.push(rel + "  " + prim + "  -> " + where + " " + name); return; }
    take(d[1]);
  }
  // An object, written inline or bound to a module-level name; `read` decides
  // what is taken from its span.
  function withObject(span, where, read) {
    var t = _trimmed(masked, span);
    if (!t) return;
    if (masked[t.start] === "{") { read(t); return; }
    var name = src.slice(t.start, t.end + 1);
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return;
    var od = new RegExp("(?:var|let|const)\\s+" + name +
      "\\s*=\\s*(?:Object\\.freeze\\s*\\()?\\{").exec(src);
    var osp = od ? _bracedFrom(masked, od.index) : null;
    if (!osp) { unresolved.push(rel + "  " + prim + "  -> " + where + " " + name); return; }
    read(osp);
  }
  // The `allow` array on a shape call's options argument: extra keys the shape
  // accepts without declaring a rule for them.
  function takeAllowList(span) {
    withObject(span, "shape options", function (osp) {
      var depth = 0;
      for (var i = osp.start; i <= osp.end; i += 1) {
        var c = masked[i];
        if (c === "{" || c === "[" || c === "(") { depth += 1; continue; }
        if (c === "}" || c === "]" || c === ")") { depth -= 1; continue; }
        if (depth !== 1) continue;
        if (masked.slice(i, i + 5) !== "allow") continue;
        var j = i + 5;
        while (j <= osp.end && /\s/.test(masked[j])) j += 1;
        if (masked[j] !== ":") continue;
        takeKeyList({ start: j + 1, end: osp.end - 1 }, "shape allow");
        return;
      }
    });
  }
  ALLOWLIST_CALLS.forEach(function (form) {
    var re = new RegExp("\\b" + form.call + "\\s*\\(\\s*" + optsParam + "\\s*,", "g");
    re.lastIndex = body.start;
    var m;
    while ((m = re.exec(masked)) !== null && m.index < body.end) {
      if (inNested(m.index)) continue;
      var openParen = masked.indexOf("(", m.index);
      if (openParen === -1) continue;
      var args = _argSpans(masked, openParen);
      if (args.length < 2) continue;
      if (form.arg === "array") { takeKeyList(args[1], "allowlist"); continue; }
      withObject(args[1], "shape schema", function (sp) { takeFields(sp); });
      if (args.length >= 6) takeAllowList(args[5]);
    }
  });
  return accepted;
}

// One file's worth of the comparison, taking source rather than a path so a
// fixture can drive it. The no-@opts case cannot be pinned against the tree,
// because once those blocks are documented they all carry a section again, and
// a reintroduced skip would go unnoticed.
function _analyze(src, rel) {
  var rows = [];
  var measurable = 0;
  var notMeasurable = 0;
  var withOpts = 0;
  var unresolved = [];
  var masked = _mask(src);
  (function () {
    var m;
    BLOCK_RE.lastIndex = 0;
    while ((m = BLOCK_RE.exec(src)) !== null) {
      var blk = m[0];
      if (blk.indexOf("@primitive") === -1) continue;
      // A block with NO @opts section is measured rather than skipped. Skipping
      // it was a blind spot over exactly the most complete form of this
      // omission: `b.fedcm.config` accepted six options and documented none,
      // and `b.mail.crypto.pgp.sign` and `.verify` accepted nine between them,
      // all while the gate passed because neither block had a section to
      // compare against.
      var optsAt = blk.search(/@opts\b/);
      if (optsAt !== -1) withOpts += 1;
      var prim = (blk.match(/@primitive\s+(\S+)/) || [])[1] || "";
      var documented = optsAt === -1 ? Object.create(null) : _documentedNames(blk, optsAt);
      var segment = prim.split(".").pop();

      var picked = null;
      _candidates(masked, m.index + blk.length, segment).forEach(function (cand) {
        if (picked) return;
        var body = _bracedFrom(masked, cand.index);
        if (!body) return;
        var params = cand.params.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
        var optsParam = params.length ? params[params.length - 1].replace(/\s*=.*$/, "") : null;
        if (!optsParam || !/^[A-Za-z_$][\w$]*$/.test(optsParam)) return;
        var spans = _nestedSpans(masked, body);
        var accepted = _acceptedNames(src, masked, body, spans, optsParam, rel, prim, unresolved);
        if (Object.keys(accepted).length === 0) return;
        picked = { accepted: accepted };
      });
      if (!picked) { notMeasurable += 1; continue; }
      measurable += 1;

      var seams = TEST_SEAMS[prim] || {};
      var missing = Object.keys(picked.accepted).filter(function (n) {
        if (documented[n]) return false;
        if (n.charAt(0) === "_") return false;
        return !seams[n];
      }).sort();
      rows.push({
        rel: rel,
        line: src.slice(0, m.index).split("\n").length,
        prim: prim,
        accepted: picked.accepted,
        documented: documented,
        missing: missing,
      });
    }
  }());
  return { rows: rows, measurable: measurable, notMeasurable: notMeasurable,
           withOpts: withOpts, unresolved: unresolved };
}

var WALK = collect();

function testTheComparisonHasSomethingToCompare() {
  // A green verdict over an empty scan is the failure this check exists for.
  // If the body window or the allowlist pattern breaks, every block becomes
  // unmeasurable and the gate passes while comparing nothing.
  check("blocks carrying an @opts section were found",
    WALK.withOpts > 800, "withOpts=" + WALK.withOpts);
  check("a useful share of them has an allowlist on its own opts parameter",
    WALK.measurable > 150, "measurable=" + WALK.measurable +
    " notMeasurable=" + WALK.notMeasurable);
  check("and the comparison ran against those blocks",
    WALK.rows.length === WALK.measurable,
    "rows=" + WALK.rows.length + " measurable=" + WALK.measurable);
  // An allowlist the gate cannot read is the one case where "unmeasurable" is a
  // defect rather than a fact about the primitive: the keys exist, so the
  // comparison is possible and something about the instrument is in the way.
  // Passing over it is how a named allowlist stayed invisible while the
  // aggregate threshold above reported a healthy count.
  check("every allowlist a primitive hands to validateOpts could be read" +
        (WALK.unresolved.length ? " (" + WALK.unresolved.join("; ") + ")" : ""),
    WALK.unresolved.length === 0);
}

function testEveryAcceptedOptionIsDocumented() {
  var offenders = WALK.rows.filter(function (r) { return r.missing.length > 0; });
  var lines = offenders.map(function (r) {
    return r.rel + ":" + r.line + " " + r.prim + " accepts but documents nowhere: " +
      r.missing.join(" ");
  });
  check("every option a primitive accepts is one its block documents" +
        (lines.length ? " (" + lines.slice(0, 6).join("; ") +
          (lines.length > 6 ? "; +" + (lines.length - 6) + " more" : "") + ")" : ""),
    lines.length === 0);
}

function testTheSeamExemptionsStayHonest() {
  var stale = [];
  var published = [];
  var redundant = [];
  Object.keys(TEST_SEAMS).forEach(function (prim) {
    var row = WALK.rows.filter(function (r) { return r.prim === prim; })[0];
    Object.keys(TEST_SEAMS[prim]).forEach(function (name) {
      if (name.charAt(0) === "_") redundant.push(prim + "." + name);
      if (!row) { stale.push(prim + " is no longer measured"); return; }
      // An exemption for an option the primitive no longer accepts is excusing
      // nothing, and hides that the seam was removed.
      if (!row.accepted[name]) stale.push(prim + "." + name + " is no longer accepted");
      // One that has since been documented became operator surface, and the
      // exemption is now hiding a real entry from this gate.
      if (row.documented[name]) published.push(prim + "." + name + " is documented now");
    });
  });
  check("every exempted seam is still an option its primitive accepts" +
        (stale.length ? " (" + stale.join("; ") + ")" : ""), stale.length === 0);
  check("and none of them has become documented operator surface" +
        (published.length ? " (" + published.join("; ") + ")" : ""), published.length === 0);
  check("and none is underscore-prefixed, which the convention already covers" +
        (redundant.length ? " (" + redundant.join("; ") + ")" : ""), redundant.length === 0);
  check("every exempted seam records what it injects",
    Object.keys(TEST_SEAMS).every(function (prim) {
      return Object.keys(TEST_SEAMS[prim]).every(function (n) {
        return typeof TEST_SEAMS[prim][n] === "string" && TEST_SEAMS[prim][n].length > 20;
      });
    }));
}

function testTheInstrumentReadsAFactoryNestedPrimitive() {
  // The defect that made the first measurement 6x too large: a primitive
  // declared inside a create() factory, whose body must end at its own brace
  // rather than at the factory's. b.auth.oauth.parseCallback calls no
  // validateOpts, so it must not be credited with the arrays that follow it
  // inside create().
  var oauth = WALK.rows.filter(function (r) {
    return r.prim === "b.auth.oauth.parseCallback";
  });
  check("a primitive nested in a factory is not credited with the factory's " +
        "later allowlists", oauth.length === 0,
    oauth.length ? JSON.stringify(Object.keys(oauth[0].accepted)) : "");

  // And the opposite direction: a middleware whose implementation is called
  // `create` is still measured, which requiring the primitive's own name broke.
  var cors = WALK.rows.filter(function (r) { return r.prim === "b.middleware.cors"; });
  check("a primitive implemented by a differently-named function is measured",
    cors.length === 1 && !!cors[0].accepted.allowPrivateNetwork,
    cors.length ? JSON.stringify(Object.keys(cors[0].accepted).slice(0, 4)) : "not found");

  // The blind spot that let a block documenting NOTHING pass: a block with no
  // @opts section had nothing to compare against, so three primitives accepted
  // fifteen options between them and the gate stayed silent. It takes a fixture
  // to pin, not the tree: once those blocks are documented they carry a section
  // again, and a reintroduced `if (optsAt === -1) continue` passes every
  // assertion made against real files.
  var noOptsFixture = [
    "/**",
    " * @primitive b.fixture.noOptsBlock",
    " * @signature b.fixture.noOptsBlock(opts)",
    " *",
    " * A primitive that accepts options and documents none of them.",
    " */",
    "function noOptsBlock(opts) {",
    "  validateOpts(opts, [\"alpha\", \"beta\"], \"fixture.noOptsBlock\");",
    "  return opts.alpha;",
    "}",
  ].join("\n");
  var fx = _analyze(noOptsFixture, "fixture.js");
  check("a block with no @opts section is measured, not skipped",
    fx.measurable === 1, "measurable=" + fx.measurable + " notMeasurable=" + fx.notMeasurable);
  check("and every option it accepts is reported as undocumented",
    fx.rows.length === 1 && fx.rows[0].missing.join(",") === "alpha,beta",
    fx.rows.length ? fx.rows[0].missing.join(",") : "no row");

  // The same blind spot one level along: an allowlist handed over by NAME. The
  // inline-array pattern found no keys, so the block was counted unmeasurable
  // and its undocumented options were never compared. A fixture pins it for the
  // same reason as the one above.
  var namedFixture = [
    "var FIXTURE_ALLOWED = [\"gamma\", \"delta\"];",
    "/**",
    " * @primitive b.fixture.namedAllowlist",
    " * @signature b.fixture.namedAllowlist(opts)",
    " *",
    " * A primitive whose allowlist is a module-level array.",
    " *",
    " * @opts",
    " *   gamma: string,   // documented",
    " */",
    "function namedAllowlist(opts) {",
    "  validateOpts(opts, FIXTURE_ALLOWED, \"fixture.namedAllowlist\");",
    "  return opts.gamma;",
    "}",
  ].join("\n");
  var nf = _analyze(namedFixture, "fixture.js");
  check("an allowlist passed by name is resolved, not counted unmeasurable",
    nf.measurable === 1, "measurable=" + nf.measurable + " notMeasurable=" + nf.notMeasurable);
  check("and its undocumented option is reported",
    nf.rows.length === 1 && nf.rows[0].missing.join(",") === "delta",
    nf.rows.length ? nf.rows[0].missing.join(",") : "no row");

  // And a named allowlist the gate CANNOT read must fail by name rather than
  // pass as one more unmeasurable block, which is what made the first two
  // blind spots survive: the aggregate threshold stayed green over them.
  var opaqueFixture = namedFixture.replace("var FIXTURE_ALLOWED = [\"gamma\", \"delta\"];",
    "var FIXTURE_ALLOWED = require(\"./elsewhere\").KEYS;");
  var of = _analyze(opaqueFixture, "fixture.js");
  check("an unreadable allowlist is reported, not skipped",
    of.unresolved.length === 1, JSON.stringify(of.unresolved));

  // The call forms. Reading only `validateOpts(` left 58 of the 413 allowlist
  // sites in lib/ invisible, and the gate reported clean over them: the mail
  // listeners validate with `checkOrThrow` and several primitives declare their
  // contract as a `shape` schema, whose field names are the allowlist because a
  // key outside the schema is refused. One fixture per form, so dropping a form
  // from ALLOWLIST_CALLS fails here rather than going quiet.
  [
    { form: "checkOrThrow", body: "validateOpts.checkOrThrow(opts, [\"one\", \"two\"], \"f\", E, \"f/bad\");" },
    { form: "check",        body: "validateOpts.check(opts, [\"one\", \"two\"], \"f\");" },
    { form: "shape",        body: "validateOpts.shape(opts, { one: { rule: \"optional-string\" }, " +
                                  "two: function (v) { return v; } }, \"f\", E, \"f/bad\");" },
    // A QUOTED schema key. The cursor has to land before the opening quote or
    // the field-delimiter check rejects every quoted field, which read as a
    // schema that declares nothing and let the option through.
    { form: "shapeQuoted",  body: "validateOpts.shape(opts, { one: \"optional-string\", " +
                                  "\"two\": \"optional-string\" }, \"f\", E, \"f/bad\");" },
    // The extra keys a shape accepts through its sixth argument's `allow`
    // array, inline and by name.
    { form: "shapeAllow",   body: "validateOpts.shape(opts, { one: \"optional-string\" }, " +
                                  "\"f\", E, \"f/bad\", { allow: [\"two\"] });" },
  ].forEach(function (c) {
    var fx2 = _analyze([
      "/**",
      " * @primitive b.fixture." + c.form,
      " * @signature b.fixture." + c.form + "(opts)",
      " *",
      " * A primitive validating through " + c.form + ".",
      " *",
      " * @opts",
      " *   one: string,   // documented",
      " */",
      "function " + c.form + "(opts) {",
      "  " + c.body,
      "  return opts.one;",
      "}",
    ].join("\n"), "fixture.js");
    check("the " + c.form + " call form is read, and its undocumented option reported",
      fx2.measurable === 1 && fx2.rows.length === 1 && fx2.rows[0].missing.join(",") === "two",
      "measurable=" + fx2.measurable + " missing=" +
        (fx2.rows.length ? fx2.rows[0].missing.join(",") : "(no row)"));
  });

  // The three that drove the finding, so dropping their entries fails here too.
  [["b.fedcm.config", "disconnect_endpoint"],
   ["b.mail.crypto.pgp.sign", "passphrase"],
   ["b.mail.crypto.pgp.verify", "armored"]].forEach(function (pair) {
    var row = WALK.rows.filter(function (r) { return r.prim === pair[0]; })[0];
    check(pair[0] + " is measured and documents " + pair[1],
      !!row && !!row.accepted[pair[1]] && !!row.documented[pair[1]],
      row ? "accepted=" + !!row.accepted[pair[1]] + " documented=" + !!row.documented[pair[1]]
          : "block not measured at all");
  });
}

async function run() {
  testTheComparisonHasSomethingToCompare();
  testEveryAcceptedOptionIsDocumented();
  testTheSeamExemptionsStayHonest();
  testTheInstrumentReadsAFactoryNestedPrimitive();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[operator-doc-opts-contract] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
