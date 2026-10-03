// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A comment block that names any of its primitive's error codes names all of
 * them.
 *
 * An operator reads the block to learn what to catch, and a partial list sends
 * them into production with a branch missing. `b.csp.build` named one of its
 * nine refusals, so `csp/header-injection`, `csp/unsafe-keyword` and
 * `csp/catch-all-source` reached nobody; `b.mail.crypto.smime.checkCert`
 * attributed the SHA-1 and short-RSA refusals to `mail-crypto/smime/bad-cert`
 * when they arrive as `refused-hash` and `rsa-too-small`.
 *
 * A block that names no code at all is a different question and is out of
 * scope: it documents nothing to be partial about.
 *
 * Scope boundary, stated rather than allowlisted: the block must sit above a
 * function declaration, and the bodies of any functions nested inside it are
 * removed before the codes are read. A code constructed inside a nested
 * function is thrown when THAT function runs — from a returned handle, a
 * listener, a worker callback — so attributing it to the primitive the block
 * describes would be wrong, while the throws the outer function makes itself
 * are exactly what the block is supposed to list.
 * `testTheScopeBoundaryIsNotSwallowingTheWork` reports how many blocks had a
 * nested body removed and how many the brace scan could not read at all.
 *
 * The full list of omissions is written to
 * `.test-output/operator-doc-error-codes.log`, because the failure names more
 * blocks than fit in one assertion message.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var ROOT = nodePath.join(__dirname, "..", "..");
var LIB  = nodePath.join(ROOT, "lib");

// An error code: two or more slash-separated lowercase segments.
var CODE_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\/[a-z0-9]+(?:-[a-z0-9]+)*){1,3}$/;

// Two readings, each used for the property it has.
//
// ENUMERATING the call shapes that build a code is PRECISE, which is what
// deciding the error-namespace vocabulary needs: `new <X>Error("ns/kind"`, and
// the argument a shared validator takes right after the error CLASS it builds.
// Keying on the class is what keeps `setHeader("Content-Type",
// "application/json")` out of the vocabulary.
//
// It is not COMPLETE, and nothing keeps it complete. A code also reaches an
// error through an options object (`{ errorClass, code }`, and the same object
// with `ErrorClass`, `typeCode` or `sizeCode` instead), through the class's own
// `.factory` or a one-name alias of it, through a local `_makeError(cls, code,
// msg)` helper, and as the SECOND argument of a message-first class. Each of
// those was found one at a time, by a reviewer, after the gate had reported
// clean. So per-body extraction does not enumerate shapes at all: a code is any
// code-shaped literal in a namespace THAT FILE builds errors in, however it
// travels. Measured against the shape list over 70 in-scope blocks, the two
// agree on every undocumented code, so this costs no precision and cannot be
// defeated by a shape nobody has thought of yet.
var NEW_ERROR_RE = /new\s+[A-Za-z_$][A-Za-z0-9_$]*Error\(\s*(?:"([^"\n]+)"|'([^'\n]+)')/g;
var CLASS_THEN_CODE_RE = /[A-Za-z_$][A-Za-z0-9_$]*Error\s*,\s*(?:"([^"\n]+)"|'([^'\n]+)')/g;
var FACTORY_CALL_RE = /\.factory\(\s*(?:"([^"\n]+)"|'([^'\n]+)')/g;
var ANY_OWN_NAMESPACE_LITERAL =
  /(?:"|')([a-z0-9][a-z0-9-]*(?:\/[a-z0-9-]+){1,3})(?:"|')/g;

// A literal on the far side of an equality test, or behind `case`, is a code
// being RECOGNIZED rather than built. `b.network.dns.discoverEncrypted` reads
// `e.code === "dns/no-result"` to translate that failure into
// `dns/ddr-not-discovered`, so demanding it in the block would put a throw in
// the documentation that the primitive specifically does not make.
var COMPARED_NOT_BUILT = /(?:===|!==|==|!=|\bcase)\s*$/;

// A code can also be composed in a SHARED builder from the prefix a module hands
// it: `var _resolveProfile = gateContract.makeProfileResolver({ codePrefix:
// "safe-icap" })` makes `safe-icap/bad-profile` reachable from a body that calls
// `_resolveProfile`, with the literal living in gate-contract.js. Those codes are
// invisible to any reading of the body alone, so the builder's suffixes are read
// out of gate-contract.js once and attributed to a body only when it calls that
// module's own alias for the builder.
var BUILDER_ALIAS_RE = new RegExp(
  "(?:var|let|const)\\s+([A-Za-z_$][A-Za-z0-9_$]*)\\s*=\\s*" +
  "[A-Za-z_$][A-Za-z0-9_$.]*\\.([A-Za-z_$][A-Za-z0-9_$]*)\\(" +
  "((?:(?!\\}\\s*\\))[\\s\\S])*)", "g");
var CODE_PREFIX_RE = /code[Pp]refix\s*:\s*"([a-z][a-z0-9-]*(?:\/[a-z0-9-]+)*)"/;

// A builder reaches suffixes its own body never spells: `makeProfileResolver`
// raises "/bad-posture" through `_postureProfileOrThrow`. Reading one body alone
// under-reports, so each body's suffixes are unioned with those of the sibling
// functions it calls, followed to a fixed point and guarded against cycles.
function builderSuffixes(gateContractSrc) {
  var bodies = {};
  var fnRe = /^function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm;
  var m;
  while ((m = fnRe.exec(gateContractSrc)) !== null) {
    var rest = gateContractSrc.slice(m.index);
    var end = rest.search(/\n\}/);
    bodies[m[1]] = end === -1 ? rest : rest.slice(0, end);
  }
  var names = Object.keys(bodies);
  var own = {};
  var calls = {};
  names.forEach(function (name) {
    var sufs = {};
    var sm;
    var sufRe = /(?:"|')(\/[a-z][a-z0-9-]*)(?:"|')/g;
    while ((sm = sufRe.exec(bodies[name])) !== null) sufs[sm[1]] = true;
    own[name] = sufs;
    calls[name] = names.filter(function (other) {
      return other !== name && new RegExp("\\b" + other + "\\s*\\(").test(bodies[name]);
    });
  });
  function reach(name, seen) {
    if (seen[name]) return {};
    seen[name] = true;
    var acc = Object.assign({}, own[name]);
    calls[name].forEach(function (callee) {
      Object.assign(acc, reach(callee, seen));
    });
    return acc;
  }
  var out = {};
  names.forEach(function (name) {
    var all = Object.keys(reach(name, {}));
    if (all.length) out[name] = all.sort();
  });
  return out;
}

// alias name -> the codes a body calling it can raise.
function composedByAliasIn(text, suffixesByBuilder) {
  var out = {};
  var m;
  BUILDER_ALIAS_RE.lastIndex = 0;
  while ((m = BUILDER_ALIAS_RE.exec(text)) !== null) {
    var sufs = suffixesByBuilder[m[2]];
    if (!sufs) continue;
    var pm = CODE_PREFIX_RE.exec(m[3]);
    if (!pm) continue;
    out[m[1]] = sufs.map(function (s) { return pm[1] + s; });
  }
  return out;
}

// Every code-shaped literal in a namespace this file builds errors in.
function codesIn(text, ownNamespaces) {
  var out = {};
  var m;
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  while ((m = ANY_OWN_NAMESPACE_LITERAL.exec(text)) !== null) {
    if (!CODE_RE.test(m[1]) || !ownNamespaces[m[1].split("/")[0]]) continue;
    if (COMPARED_NOT_BUILT.test(text.slice(0, m.index))) continue;
    out[m[1]] = true;
  }
  return out;
}

// The nine IANA top-level media types. A media type is written exactly like a
// code, so without this the vocabulary would adopt `application` or `text` from
// a throw that reports an unsupported type, and then demand every
// `application/...` literal in a documented body.
var MEDIA_TOP_LEVEL = {
  application: 1, audio: 1, example: 1, font: 1, image: 1,
  message: 1, model: 1, multipart: 1, text: 1, video: 1,
};

// A code-shaped literal inside a `throw` or a `reject(...)`, whatever built it.
//
// This is the rule that makes the vocabulary complete, and it replaces three
// rounds of guessing at call shapes. Anchoring on an error CLASS beside the
// literal is precise but blind by construction: `lib/guard-markdown.js` builds
// every error through `var _err = GuardMarkdownError.factory`, `lib/a2a.js`
// through `errorClass.factory(...)` on a parameter, and `lib/sql.js` passes the
// code as a trailing argument. Each is a different shape and none carries the
// class beside the literal, so all three modules had an EMPTY vocabulary, which
// filtered out every code and left their documented blocks silently unchecked.
//
// Every error code reaches an operator by being thrown, so that is the construct
// to read. A statement ends at the first `;` outside parentheses, which a throw
// expression does not contain.
function namespacesFromThrows(text, out) {
  var re = /\b(?:throw|reject)\b/g;
  var m;
  while ((m = re.exec(text)) !== null) {
    var depth = 0;
    var end = m.index;
    for (; end < text.length; end += 1) {
      var c = text[end];
      if (c === "(") depth += 1;
      else if (c === ")") { depth -= 1; if (depth < 0) break; }
      else if (c === ";" && depth === 0) break;
    }
    var span = text.slice(m.index, end);
    ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
    var lm;
    while ((lm = ANY_OWN_NAMESPACE_LITERAL.exec(span)) !== null) {
      if (!CODE_RE.test(lm[1])) continue;
      var ns = lm[1].split("/")[0];
      if (!MEDIA_TOP_LEVEL[ns]) out[ns] = true;
    }
  }
}

// The namespace vocabulary. Construction sites anchored on the error class give
// the precise core; the throw rule above makes it complete.
function namespacesIn(text) {
  var out = {};
  [NEW_ERROR_RE, CLASS_THEN_CODE_RE, FACTORY_CALL_RE].forEach(function (re) {
    re.lastIndex = 0;
    var m;
    while ((m = re.exec(text)) !== null) {
      var lit = m[1] !== undefined ? m[1] : m[2];
      if (!lit || !CODE_RE.test(lit)) continue;
      var ns = lit.split("/")[0];
      if (!MEDIA_TOP_LEVEL[ns]) out[ns] = true;
    }
  });
  namespacesFromThrows(text, out);
  return out;
}

var BACKTICK_RE = /`([^`\n]{1,160})`/g;
var BLOCK_RE    = /\/\*\*[\s\S]*?\*\//g;

function walk(dir, out) {
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (ent) {
    var full = nodePath.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === "vendor" || ent.name === "node_modules") return;
      walk(full, out);
      return;
    }
    if (ent.isFile() && /\.js$/.test(ent.name)) out.push(full);
  });
  return out;
}

// Comment blocks become same-length runs of spaces, so a code only MENTIONED in
// prose never counts as constructed and every line number stays put.
function stripBlocks(src) {
  return src.replace(BLOCK_RE, function (m) { return m.replace(/[^\n]/g, " "); });
}

// A trailing slash means the literal is a PREFIX a builder completes, not a
// code: `"backup/"` names no refusal an operator can catch.
function isWholeCode(codeStr) {
  var last = codeStr.slice(codeStr.lastIndexOf("/") + 1);
  return last.length > 0;
}

function lineOf(src, index) { return src.slice(0, index).split("\n").length; }

// The body the block describes: from the end of the block to the first closing
// brace at column 0, which is where a top-level function ends.
//
// Returns null when the block does not sit above a function declaration. A
// block over `var SafeSqlError = frameworkError.defineMessageFirstClass(...)`
// describes an error CLASS, and reading on to the next `\n}` would collect the
// codes of whatever function follows it.
var OPENS_A_FUNCTION = /^\s*(?:async\s+)?function\s+[A-Za-z_$]/;

function bodyAfter(code, blockEnd) {
  var after = code.slice(blockEnd);
  if (!OPENS_A_FUNCTION.test(after)) return null;
  var end = after.search(/\n\}/);
  return end === -1 ? after : after.slice(0, end);
}

// Everything past the line that opens the function. The declaration itself is
// excluded so its own `function` keyword does not read as a nested one.
function pastDeclaration(body) {
  var at = body.search(/\{[ \t]*$/m);
  return at === -1 ? body : body.slice(at);
}

// The contents of every string and every comment become filler, so a brace
// written inside one cannot move the depth counter. Length and newlines are
// preserved, so an offset into the masked text addresses the same character of
// the original.
function maskLiteralsAndComments(text) {
  var out = text.split("");
  var i = 0;
  while (i < out.length) {
    var ch = out[i];
    if (ch === "/" && out[i + 1] === "/") {
      var a = i;
      while (a < out.length && out[a] !== "\n") { out[a] = " "; a += 1; }
      i = a;
      continue;
    }
    if (ch === "/" && out[i + 1] === "*") {
      var b = i + 2;
      while (b < out.length && !(out[b] === "*" && out[b + 1] === "/")) b += 1;
      var stop = Math.min(b + 2, out.length);
      for (var k = i; k < stop; k += 1) { if (out[k] !== "\n") out[k] = " "; }
      i = stop;
      continue;
    }
    if (ch !== '"' && ch !== "'" && ch !== "`") { i += 1; continue; }
    var quote = ch;
    var j = i + 1;
    while (j < out.length) {
      if (out[j] === "\\") { j += 2; continue; }
      if (out[j] === quote) break;
      if (quote !== "`" && out[j] === "\n") break;
      if (out[j] !== "\n") out[j] = "x";
      j += 1;
    }
    i = j + 1;
  }
  return out.join("");
}

// The keywords whose parenthesized head is followed by a BLOCK rather than a
// function body.
var CONTROL_HEAD = { "if": 1, "for": 1, "while": 1, "switch": 1, "catch": 1, "with": 1 };

function skipBackWhitespace(text, at) {
  var i = at;
  while (i >= 0 && /\s/.test(text[i])) i -= 1;
  return i;
}

// Does the brace at `at` open a function body?
//
// `function` is only one of three spellings. A shorthand object or class method
// (`async verifyBundle(id, opts) {`) and an arrow (`=> {`) open one too, and
// reading only the keyword attributed every method of a returned handle to the
// factory that built it: `b.backup.bundleAdapterStorage` drew 26 codes that way,
// among them two that are reported in a result's `errors` array and never
// thrown at all.
//
// So this asks the other question: does the brace open a BLOCK? That
// set is closed and short, and anything outside it is treated as a function
// body, which costs coverage when it is wrong instead of demanding a code the
// primitive does not throw.
function opensFunctionBody(masked, at) {
  var i = skipBackWhitespace(masked, at - 1);
  if (i < 0) return false;
  if (masked[i] === ">" && masked[i - 1] === "=") return true;      // => {
  if (masked[i] !== ")") {
    // `else {`, `try {`, `do {`, `finally {`, a bare block, or an object
    // literal after `=`, `(`, `,`, `:` or `return`. None is a function body.
    return false;
  }
  var depth = 0;
  while (i >= 0) {
    if (masked[i] === ")") depth += 1;
    else if (masked[i] === "(") {
      depth -= 1;
      if (depth === 0) break;
    }
    i -= 1;
  }
  if (i < 0) return true;                                           // unreadable head
  var j = skipBackWhitespace(masked, i - 1);
  var end = j;
  while (j >= 0 && /[A-Za-z0-9_$]/.test(masked[j])) j -= 1;
  if (j === end) return true;                                       // `)(` and the like
  var word = masked.slice(j + 1, end + 1);
  return !CONTROL_HEAD[word];
}

// Spans covering each nested function body, or null when the brace scan does
// not come back balanced. Scanning starts past the declaration's own opening
// brace: `bodyAfter` includes that brace and stops before the matching close,
// so counting it would leave every body one deep. A body the scan cannot read
// is reported as unreadable rather than read wrongly, which falls back to
// holding the whole block back instead of answering over a skewed count.
function nestedFunctionSpans(body) {
  var masked = maskLiteralsAndComments(body);
  var declEnd = masked.search(/\{/);
  if (declEnd === -1) return null;
  var spans = [];
  var depth = 0;
  var spanStart = -1;
  var spanDepth = -1;
  for (var i = declEnd + 1; i < masked.length; i += 1) {
    var c = masked[i];
    if (c === "{") {
      depth += 1;
      if (spanStart === -1 && opensFunctionBody(masked, i)) {
        spanStart = i;
        spanDepth = depth;
      }
    } else if (c === "}") {
      if (spanStart !== -1 && depth === spanDepth) {
        spans.push([spanStart, i + 1]);
        spanStart = -1;
        spanDepth = -1;
      }
      depth -= 1;
      if (depth < 0) return null;
    }
  }
  if (depth !== 0 || spanStart !== -1) return null;
  return spans;
}

function withoutSpans(body, spans) {
  var out = body.split("");
  spans.forEach(function (s) {
    for (var i = s[0]; i < s[1] && i < out.length; i += 1) {
      if (out[i] !== "\n") out[i] = " ";
    }
  });
  return out.join("");
}

var FILES = walk(LIB, []);

// ---- The vocabulary: namespaces the tree really builds errors in. ----
var NAMESPACES = {};
var STRIPPED = {};
var OWN_NAMESPACES = {};
var COMPOSED_BY_ALIAS = {};
var BUILDER_SUFFIXES = builderSuffixes(
  stripBlocks(nodeFs.readFileSync(nodePath.join(LIB, "gate-contract.js"), "utf8")));
FILES.forEach(function (full) {
  var rel = nodePath.relative(ROOT, full).replace(/\\/g, "/");
  var code = stripBlocks(nodeFs.readFileSync(full, "utf8"));
  STRIPPED[rel] = code;
  OWN_NAMESPACES[rel] = namespacesIn(code);
  COMPOSED_BY_ALIAS[rel] = composedByAliasIn(code, BUILDER_SUFFIXES);
  Object.keys(OWN_NAMESPACES[rel]).forEach(function (ns) { NAMESPACES[ns] = true; });
  Object.keys(COMPOSED_BY_ALIAS[rel]).forEach(function (alias) {
    COMPOSED_BY_ALIAS[rel][alias].forEach(function (c) {
      NAMESPACES[c.split("/")[0]] = true;
      OWN_NAMESPACES[rel][c.split("/")[0]] = true;
    });
  });
});

// ---- Walk every @primitive block. ----
function collect() {
  var inScope = [];
  var heldBack = [];
  var narrowed = 0;
  var notAFunction = 0;
  FILES.forEach(function (full) {
    var rel = nodePath.relative(ROOT, full).replace(/\\/g, "/");
    var src = nodeFs.readFileSync(full, "utf8");
    var code = STRIPPED[rel];
    var m;
    BLOCK_RE.lastIndex = 0;
    while ((m = BLOCK_RE.exec(src)) !== null) {
      var blk = m[0];
      if (blk.indexOf("@primitive") === -1) continue;

      var documented = {};
      var bm;
      BACKTICK_RE.lastIndex = 0;
      while ((bm = BACKTICK_RE.exec(blk)) !== null) {
        var inner = bm[1];
        if (!CODE_RE.test(inner)) continue;
        if (!NAMESPACES[inner.split("/")[0]]) continue;
        documented[inner] = true;
      }
      if (Object.keys(documented).length === 0) continue;

      var prim = (blk.match(/@primitive\s+(\S+)/) || [])[1] || "(unnamed)";
      var body = bodyAfter(code, m.index + blk.length);
      if (body === null) { notAFunction += 1; continue; }
      var entry = {
        file:       rel,
        line:       lineOf(src, m.index),
        prim:       prim,
        documented: Object.keys(documented).sort(),
      };
      // A code built inside a callback belongs to that callback, not to the
      // primitive the block describes, so only the nested BODIES are removed.
      // Holding the whole primitive back instead would discard the throws the
      // outer function makes itself, which is most of what there is to check:
      // `b.deprecate.warn` throws `deprecate/used-in-error-mode` from its own
      // body and merely passes a callback to a map.
      var spans = nestedFunctionSpans(body);
      if (spans === null) { heldBack.push(entry); continue; }
      var own = body;
      if (spans.length) {
        own = withoutSpans(body, spans);
        narrowed += 1;
      }
      var thrown = codesIn(own, OWN_NAMESPACES[rel]);
      Object.keys(COMPOSED_BY_ALIAS[rel]).forEach(function (alias) {
        if (!new RegExp("\\b" + alias + "\\s*\\(").test(own)) return;
        COMPOSED_BY_ALIAS[rel][alias].forEach(function (c) { thrown[c] = true; });
      });
      entry.missing = Object.keys(thrown)
        .filter(isWholeCode)
        .filter(function (c) { return !documented[c]; })
        .sort();
      inScope.push(entry);
    }
  });
  return {
    inScope:      inScope,
    heldBack:     heldBack,
    narrowed:     narrowed,
    notAFunction: notAFunction,
  };
}

var WALK = collect();

// The assertion message can only carry a few of the blocks. The whole list goes
// to a file so a run that fails over thirty blocks is readable without re-running
// the gate, per the same discipline the other gates follow.
function writeReport(lines) {
  var dir = nodePath.join(ROOT, ".test-output");
  var body = lines.length === 0
    ? "no block omits a code its function throws\n"
    : lines.join("\n") + "\n\n" + lines.length + " blocks, " +
      lines.reduce(function (n, l) { return n + l.split(" omits ")[1].split(" ").length; }, 0) +
      " codes\n";
  try {
    nodeFs.mkdirSync(dir, { recursive: true });
    nodeFs.writeFileSync(nodePath.join(dir, "operator-doc-error-codes.log"), body);
  } catch (_e) { /* a report that cannot be written must not fail the gate */ }
}

function testTheWalkReadTheTree() {
  var documenting = WALK.inScope.length + WALK.heldBack.length;
  check("lib/ was walked and the error vocabulary built",
        FILES.length >= 400 && Object.keys(NAMESPACES).length >= 100,
        FILES.length + " files, " + Object.keys(NAMESPACES).length + " namespaces");
  check("the walk found blocks that document error codes",
        documenting >= 100, documenting + " blocks name at least one code");

  // The premise, measured rather than assumed. A file whose vocabulary comes
  // back EMPTY has every code-shaped literal filtered out, so the comparison
  // runs over nothing and the gate reports clean for it. That is how three
  // modules building errors through a factory went unchecked while this gate
  // claimed their lists were complete. A regression in the vocabulary would
  // collapse this count and has to fail here, not pass quietly.
  var withVocabulary = Object.keys(OWN_NAMESPACES).filter(function (rel) {
    return Object.keys(OWN_NAMESPACES[rel]).length > 0;
  }).length;
  check("most of lib/ contributes an error vocabulary, so the comparison is not " +
        "running over an empty set",
        withVocabulary * 2 > FILES.length,
        withVocabulary + " of " + FILES.length + " files build errors in a named namespace");
}

function testEveryDocumentedCodeListIsComplete() {
  var partial = WALK.inScope.filter(function (e) { return e.missing.length; });
  var lines = partial.map(function (e) {
    return e.file + ":" + e.line + " " + e.prim + " omits " + e.missing.join(" ");
  });
  writeReport(lines);
  check("every block that names an error code names all the codes its function throws" +
        (lines.length ? " (" + lines.slice(0, 8).join("; ") +
          (lines.length > 8 ? "; +" + (lines.length - 8) + " more" : "") + ")" : ""),
        lines.length === 0);
}

function testBuilderSuffixesFollowDelegation() {
  // `makeProfileResolver` raises "/bad-posture" through a sibling it calls, so
  // its own body never spells that suffix. Reading one body alone passed three
  // primitives whose posture refusal was undocumented, which is what this
  // control is here to prevent recurring.
  var gc = stripBlocks(nodeFs.readFileSync(nodePath.join(LIB, "gate-contract.js"), "utf8"));
  var at = gc.search(/^function makeProfileResolver\(/m);
  var rest = at === -1 ? "" : gc.slice(at);
  var endAt = rest.search(/\n\}/);
  var ownBody = endAt === -1 ? rest : rest.slice(0, endAt);
  check("the delegating builder's own body does not spell the delegated suffix",
        at !== -1 && ownBody.indexOf("/bad-posture") === -1);
  var resolved = BUILDER_SUFFIXES.makeProfileResolver || [];
  check("yet the resolved suffixes include it, so delegation is followed",
        resolved.indexOf("/bad-posture") !== -1, resolved.join(" "));
}

function testTheScopeBoundaryIsNotSwallowingTheWork() {
  // A nested function's codes are not the described primitive's to throw, so
  // those bodies come out of scope. Only the bodies: a block is held back whole
  // only when the brace scan cannot read it, and that case is reported rather
  // than silent, because a boundary that grew to hold back most of the tree
  // would be a gate that checks nothing.
  var held = WALK.heldBack.length;
  var total = WALK.inScope.length + held + WALK.notAFunction;
  check("the gate reads all but a handful of the blocks that document codes",
        WALK.inScope.length > held * 20,
        WALK.inScope.length + " read (" + WALK.narrowed +
        " with nested bodies removed), " + held + " held back whole as unreadable, " +
        WALK.notAFunction + " over something that is not a function declaration, of " + total);
  // Narrowing, not holding back, is what keeps those blocks readable. Stated
  // as a comparison against the blocks it rescued rather than as a count,
  // because a count is a number about today's tree and goes stale silently.
  check("a block with a nested body is narrowed rather than held back",
        WALK.narrowed > held,
        WALK.narrowed + " narrowed against " + held + " held back");
}

function testNestedBodiesComeOutButTheOuterFunctionStays() {
  // The control for the span scan. The outer function throws one code and the
  // callback it passes throws another; the first must survive the narrowing and
  // the second must not. A scan that stripped the whole body, or none of it,
  // fails one of these two.
  var body = [
    "function outer(x) {",
    "  if (!x) throw new FixtureError(\"fixture/outer-throw\", \"empty\");",
    "  return x.map(function (item) {",
    "    if (!item) throw new FixtureError(\"fixture/inner-throw\", \"empty item\");",
    "    return item;",
    "  });",
  ].join("\n");
  var spans = nestedFunctionSpans(body);
  check("the brace scan reads the body", spans !== null && spans.length === 1,
        spans === null ? "null" : spans.length + " spans");
  var own = withoutSpans(body, spans || []);
  var codes = Object.keys(codesIn(own, { fixture: true })).sort();
  check("the outer function's own code survives the narrowing",
        codes.indexOf("fixture/outer-throw") !== -1, codes.join(","));
  check("the callback's code does not",
        codes.indexOf("fixture/inner-throw") === -1, codes.join(","));

  // A brace inside a string or a comment must not move the counter, and an
  // unbalanced body must come back null rather than a confident wrong span.
  var tricky = [
    "function outer(x) {",
    "  var open = \"{\";",
    "  // a comment with a } in it",
    "  return x.map(function (i) { return i + \"}\"; });",
  ].join("\n");
  var trickySpans = nestedFunctionSpans(tricky);
  check("a brace inside a string or a comment does not skew the scan",
        trickySpans !== null && trickySpans.length === 1,
        trickySpans === null ? "null" : trickySpans.length + " spans");
  check("an unreadable body comes back null, so the block is held back whole",
        nestedFunctionSpans("function outer() {\n  foo(function () {\n") === null);
}

function testTheGateCanFail() {
  // A control, because every other assertion here is expected to pass: run the
  // same extractors over a fixture whose block omits a code its body throws.
  var fixture = [
    "var _fixtureErr = FixtureError.factory;",
    "/**",
    " * @primitive  b.fixture.only",
    " * Throws `fixture/documented` when the input is empty.",
    " */",
    "function only(x) {",
    "  if (!x) throw new FixtureError(\"fixture/documented\", \"empty\");",
    "  if (x < 0) throw new FixtureError(\"fixture/undocumented\", \"negative\");",
    "  validateOpts.requireNonEmptyString(x.name, \"name\", FixtureError, \"fixture/via-class-arg\");",
    "  if (x.big) throw FixtureError.factory(\"fixture/via-factory\", \"too big\");",
    "  if (x.odd) throw _fixtureErr(\"fixture/via-factory-alias\", \"odd\");",
    "  if (x.late) throw new FixtureError(\"late: not ready\", \"fixture/via-message-first\");",
    "  _makeError(errClass, \"fixture/via-local-helper\", \"helper\");",
    "  structuredFields.refuseControlBytes(x.hdr, {",
    "    ErrorClass: FixtureError,",
    "    code:       \"fixture/via-capital-opts\",",
    "  });",
    "  return safeJson.parseTyped(x.body, {",
    "    maxBytes:   16,",
    "    errorClass: FixtureError,",
    "    sizeCode:   \"fixture/via-size-code\",",
    "    code:       \"fixture/via-opts-object\",",
    "    label:      \"only: body is not JSON\",",
    "  });",
    "}",
    "",
  ].join("\n");
  var stripped = stripBlocks(fixture);
  var blockEnd = fixture.indexOf("*/") + 2;
  var body = bodyAfter(stripped, blockEnd);
  var own = { fixture: true };
  var thrown = Object.keys(codesIn(body, own)).sort();
  // Eight shapes, including the four a reviewer found one at a time. The point
  // is that none of them is named here: the rule reads a code-shaped literal in
  // the file's own namespace, so a ninth shape needs no change.
  var expected = ["fixture/documented", "fixture/undocumented",
    "fixture/via-capital-opts", "fixture/via-class-arg", "fixture/via-factory",
    "fixture/via-factory-alias", "fixture/via-local-helper",
    "fixture/via-message-first", "fixture/via-opts-object",
    "fixture/via-size-code"];
  check("the extractor reads a code out of every construction shape",
        thrown.join(",") === expected.join(","), thrown.join(","));
  check("the fixture body is in scope — it opens no nested function",
        !/\bfunction\b/.test(pastDeclaration(body)));
  var documented = { "fixture/documented": true };
  var missing = thrown.filter(function (c) { return !documented[c]; });
  check("the comparison reports every undocumented code, whatever shape built it",
        missing.length === expected.length - 1 &&
        missing.indexOf("fixture/documented") === -1, missing.join(","));
  // A literal outside the file's own namespaces is another module's code, named
  // for reference rather than thrown here, so it must not be demanded.
  var foreign = Object.keys(codesIn("throw other.factory(\"other/elsewhere\");", own));
  check("a code in another module's namespace is not counted as thrown here",
        foreign.length === 0, foreign.join(","));
}

async function run() {
  testTheWalkReadTheTree();
  testEveryDocumentedCodeListIsComplete();
  testBuilderSuffixesFollowDelegation();
  testTheScopeBoundaryIsNotSwallowingTheWork();
  testNestedBodiesComeOutButTheOuterFunctionStays();
  testTheGateCanFail();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[operator-doc-error-codes] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
