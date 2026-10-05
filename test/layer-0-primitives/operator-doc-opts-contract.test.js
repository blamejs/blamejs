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

function _bracedFrom(masked, at) {
  var open = masked.indexOf("{", at);
  if (open === -1) return null;
  var depth = 0;
  for (var i = open; i < masked.length; i += 1) {
    if (masked[i] === "{") depth += 1;
    else if (masked[i] === "}") { depth -= 1; if (depth === 0) return { start: open, end: i }; }
  }
  return null;
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

function _withoutSpans(text, body, spans) {
  var parts = [];
  var at = body.start;
  spans.forEach(function (s) { parts.push(text.slice(at, s.start)); at = s.end + 1; });
  parts.push(text.slice(at, body.end));
  return parts.join(" ");
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

  _libFiles(LIB, []).forEach(function (file) {
    var src = nodeFs.readFileSync(file, "utf8");
    var rel = nodePath.relative(ROOT, file).replace(/\\/g, "/");
    var r = _analyze(src, rel);
    rows = rows.concat(r.rows);
    measurable += r.measurable;
    notMeasurable += r.notMeasurable;
    withOpts += r.withOpts;
  });
  return { rows: rows, measurable: measurable, notMeasurable: notMeasurable, withOpts: withOpts };
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
        var ownSrc = _withoutSpans(src, body, _nestedSpans(masked, body));
        var vre = new RegExp("validateOpts\\s*\\(\\s*" + optsParam + "\\s*,\\s*\\[([^\\]]*)\\]", "g");
        var accepted = {};
        var vm;
        while ((vm = vre.exec(ownSrc)) !== null) {
          (vm[1].match(/"([^"]+)"|'([^']+)'/g) || []).forEach(function (q) {
            accepted[q.slice(1, -1)] = true;
          });
        }
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
  return { rows: rows, measurable: measurable, notMeasurable: notMeasurable, withOpts: withOpts };
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
