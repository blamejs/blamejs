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

// An error code: two or more slash-separated segments, each starting lowercase.
// A hyphenated part may carry uppercase after its first character, because a code
// that names an option names it as the option is spelled:
// `mail-deploy/bad-displayName`, `deliver/bad-timeout-mxLookupMs`,
// `vex/missing-documentId`. Reading lowercase only made those invisible, so a
// block omitting one of them passed.
// Kept in step with CODE_IN_TEXT_RE below: both answer "what does a code look
// like", so a shape one accepts and the other rejects is a code the gate finds
// and then silently discards. The underscore is here for the six `auth-ciba`
// codes that re-raise the CIBA and OAuth wire names.
var CODE_RE = /^[a-z][a-z0-9]*(?:-[A-Za-z0-9]+)*(?:\/[a-z0-9]+(?:[-_][A-Za-z0-9]+)*){1,3}$/;

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
// The underscore is here for the same reason as in CODE_RE and
// CODE_IN_TEXT_RE: three patterns answer "what does a code look like", and one
// that stops at the underscore makes the six `auth-ciba` wire-name codes
// invisible to whichever stage reads through it. Here that stage is the
// compared-code reader, so `err.code === "auth-ciba/expired_token"` did not
// register as the body recognising that code at all.
var ANY_OWN_NAMESPACE_LITERAL =
  /(?:"|')([a-z0-9][A-Za-z0-9-]*(?:\/[A-Za-z0-9_-]+){1,3})(?:"|')/g;

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
var CODE_PREFIX_RE = /code[Pp]refix\s*:\s*"([a-z][A-Za-z0-9-]*(?:\/[A-Za-z0-9-]+)*)"/;

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
    var sufRe = /(?:"|')(\/[a-z][A-Za-z0-9-]*)(?:"|')/g;
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

// The ten IANA top-level media types. A media type is written exactly like a
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

// The codes a body THROWS, which is the set that reaches its caller. Reading
// every code-shaped literal in the body instead demands codes the function never
// raises: `lib/worker-pool.js` builds `workerpool/post-failed`,
// `workerpool/task-failed` and `workerpool/timeout` and hands each to
// `_finishTask`, which rejects a TASK's promise rather than the `create()` call,
// so `b.workerPool.create` was asked to document eight codes its caller cannot
// see. Same span rule as the vocabulary scan above: a statement ends at the first
// `;` outside parentheses.
// Spans of `throw ...;` and `reject(...)`, where a statement ends at the first
// `;` outside parentheses.
function raisingSpans(text) {
  var spans = [];
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
    spans.push([m.index, end]);
  }
  return spans;
}

// Spans of an error-CONSTRUCTION expression: `new <X>Error( … )` and
// `<something>.factory( … )`, to the matching close paren, with what the
// expression's value is done with. An error built, assigned, decorated and thrown
// a few lines later is raised just as directly as one thrown in place:
// `unwrapWithPassphrase` in `lib/archive-wrap.js` builds
// `archive-wrap/decrypt-failed`, attaches metadata to it and throws the variable.
// One RETURNED is raised too, since a function whose value is an error exists for
// a caller to throw it. Only one passed straight to another call, and never named,
// has its fate decided elsewhere.
function constructionSpans(text) {
  var spans = [];
  var re = /new\s+[A-Za-z_$][\w$]*Error\s*\(|\.factory\s*\(/g;
  var m;
  while ((m = re.exec(text)) !== null) {
    var depth = 0;
    var i = m.index + m[0].length - 1;
    for (; i < text.length; i += 1) {
      if (text[i] === "(") depth += 1;
      else if (text[i] === ")") { depth -= 1; if (depth === 0) { i += 1; break; } }
    }
    var head = text.slice(Math.max(0, m.index - 160), m.index);
    var assigned = /(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?$/.exec(head);
    spans.push({
      start:      m.index,
      end:        i,
      assignedTo: assigned ? assigned[1] : null,
      returned:   /\breturn\s*(?:await\s+)?$/.test(head),
    });
  }
  return spans;
}

// Does the body raise the value held by this name?
function raisesName(text, name) {
  var safe = name.replace(/\$/g, "\\$");
  return new RegExp("\\bthrow\\s+" + safe + "\\b").test(text) ||
         new RegExp("\\breject\\s*\\(\\s*" + safe + "\\b").test(text);
}

// The construction holding `at`, or null.
function constructionAt(spans, at) {
  for (var i = 0; i < spans.length; i += 1) {
    if (at >= spans[i].start && at < spans[i].end) return spans[i];
  }
  return null;
}

function inAnySpan(spans, at) {
  for (var i = 0; i < spans.length; i += 1) {
    if (at >= spans[i][0] && at < spans[i][1]) return true;
  }
  return false;
}

// The codes a body RAISES into its caller.
//
// Two readings were each wrong in one direction. Taking every code-shaped
// literal in the body demanded codes the caller cannot see: `lib/worker-pool.js`
// builds `workerpool/post-failed`, `workerpool/task-failed` and
// `workerpool/timeout` and hands each to `_finishTask`, which rejects a TASK's
// promise, so `b.workerPool.create` was asked for eight codes. Taking only codes
// inside a `throw` or `reject` then lost the ones a throwing validator raises,
// since `validateOpts.checkOrThrow(opts, keys, name, ErrorClass, "ns/code")` and
// `validateOpts.requireNonEmptyString(x, label, ErrorClass, "ns/code")` carry the
// code as an argument and name no `throw` at the call site.
//
// What separates them is the error CONSTRUCTION. A code inside `new <X>Error(…)`
// or `<x>.factory(…)` that no `throw` or `reject` encloses is an error whose fate
// the body decides, and handing it to a callback is not raising it.
//
// Outside a construction, a code-shaped literal is an argument, and being an
// argument is not enough either: `lib/worker-pool.js` writes its codes a second
// time as the `reason` of an audit event, which REPORTS the code rather than
// raising it. Two shapes raise. The call carries an error class beside the code,
// which is how every shared validator takes one
// (`validateOpts.checkOrThrow(opts, keys, name, MailDeployError, "ns/code")`, and
// the `{ errorClass, code }` object form). Or the callee is a local helper that
// throws, which is how a module routes every refusal through one place:
// `lib/regex-linear.js` has `_fail(message, code)` whose body throws, so
// `_fail("…", "regex/unsupported-group")` raises that code from the caller.
var RAISING_CLASS_RE = /[A-Za-z_$][\w$]*Error\b|errorClass|ErrorClass/;

// The innermost call whose argument list contains `at`.
function enclosingCall(text, at) {
  var depth = 0;
  var i = at;
  for (; i >= 0; i -= 1) {
    var c = text[i];
    if (c === ")") depth += 1;
    else if (c === "(") { if (depth === 0) break; depth -= 1; }
  }
  if (i < 0) return null;
  var open = i;
  var head = text.slice(Math.max(0, open - 160), open);
  var nameMatch = /([A-Za-z_$][\w$]*)\s*$/.exec(head);
  var d = 0;
  var j = open;
  for (; j < text.length; j += 1) {
    if (text[j] === "(") d += 1;
    else if (text[j] === ")") { d -= 1; if (d === 0) { j += 1; break; } }
  }
  return {
    callee: nameMatch ? nameMatch[1] : null,
    args:   text.slice(open, j),
  };
}

// A local helper RAISES what it is handed when its body throws. One that only
// rejects does not raise into this caller: it settles a promise it holds, which is
// how `_finishTask` in `lib/worker-pool.js` delivers a failure to the task that
// asked for it rather than to whoever called `create`.
function raisingHelperNames(helpers) {
  var out = {};
  Object.keys(helpers || {}).forEach(function (name) {
    if (/\bthrow\b/.test(helpers[name])) out[name] = true;
  });
  return out;
}

// The helpers declared INSIDE this primitive, by name. A factory's own
// `_finishTask` is nested, so classifying only the module's top-level functions
// cannot tell whether handing it an error raises that error here.
function nestedHelperBodies(body) {
  var masked = maskLiteralsAndComments(body);
  var declEnd = masked.search(/\{/);
  if (declEnd === -1) return {};
  var nested = nestedDeclarations(masked, declEnd + 1);
  if (nested === null) return {};
  var out = {};
  nested.forEach(function (n) {
    if (n.name && n.end > n.brace) out[n.name] = body.slice(n.brace, n.end);
  });
  return out;
}

// Local helpers that take an error and do NOT throw it, which is the only case
// where handing a construction to a call keeps it away from this caller.
function deferringHelperNames(helpers) {
  var out = {};
  Object.keys(helpers || {}).forEach(function (name) {
    if (!/\bthrow\b/.test(helpers[name])) out[name] = true;
  });
  return out;
}

function codesRaisedIn(text, ownNamespaces, raisingHelpers, deferring) {
  var raising = raisingSpans(text);
  var constructions = constructionSpans(text);
  var out = {};
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  var m;
  while ((m = ANY_OWN_NAMESPACE_LITERAL.exec(text)) !== null) {
    if (!CODE_RE.test(m[1])) continue;
    if (!ownNamespaces[m[1].split("/")[0]]) continue;
    if (COMPARED_NOT_BUILT.test(text.slice(0, m.index))) continue;
    if (inAnySpan(raising, m.index)) { out[m[1]] = true; continue; }
    var built = constructionAt(constructions, m.index);
    if (built) {
      if (built.returned ||
          (built.assignedTo && raisesName(text, built.assignedTo))) {
        out[m[1]] = true;
        continue;
      }
      // Handed to another call. That reaches this caller unless the callee is a
      // local helper that demonstrably does not throw. `report(new
      // SafeJsonError("json/validation", …))` in `lib/safe-json.js` goes to a
      // callback the caller supplies and throws at once, so it does reach them;
      // `_finishTask(slot, true, new WorkerPoolError(…))` goes to a helper that
      // rejects a task's promise, so it does not.
      // From the construction's START, so the call found is the one the
      // construction is an argument to rather than the construction itself.
      var holder = enclosingCall(text, built.start);
      if (holder && holder.callee && deferring && deferring[holder.callee]) continue;
      out[m[1]] = true;
      continue;
    }
    var call = enclosingCall(text, m.index);
    if (!call) continue;
    if (RAISING_CLASS_RE.test(call.args)) { out[m[1]] = true; continue; }
    if (call.callee && raisingHelpers && raisingHelpers[call.callee]) {
      out[m[1]] = true;
    }
  }
  return out;
}

// The codes a body RECOGNIZES rather than builds, which is the set `codesIn`
// skips. A primitive that reads one of these in a catch is handling it.
function comparedCodesIn(text, ownNamespaces) {
  var out = {};
  var masked = maskLiteralsAndComments(text);
  var catches = _catchRanges(masked);
  var m;
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  while ((m = ANY_OWN_NAMESPACE_LITERAL.exec(text)) !== null) {
    if (!CODE_RE.test(m[1]) || !ownNamespaces[m[1].split("/")[0]]) continue;
    if (!COMPARED_NOT_BUILT.test(text.slice(0, m.index))) continue;
    // Comparing a code is only HANDLING it if the catch consumes it. A catch
    // that reads the code, tidies up and then re-raises the error it caught
    // leaves the caller receiving that code, so it stays part of the contract:
    // `b.auth.ciba.client.pollToken` compares `auth-ciba/expired_token`,
    // `access_denied`, `invalid_grant` and `transaction_failed` only to drop
    // its interval state, then runs `throw err`, and the blanket rule removed
    // all four from what the block had to name.
    if (_rethrowsAt(masked, catches, m.index)) continue;
    out[m[1]] = true;
  }
  return out;
}

// The codes a body compares inside a catch that then re-raises what it caught.
// Those reach the caller THROUGH this primitive even though nothing here builds
// them — they are raised by whatever this body called, recognised here, and
// passed on — so they belong in the contract rather than merely being left out
// of the handled set.
function rethrownComparedCodesIn(text, ownNamespaces) {
  var out = {};
  var masked = maskLiteralsAndComments(text);
  var catches = _catchRanges(masked);
  var m;
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  while ((m = ANY_OWN_NAMESPACE_LITERAL.exec(text)) !== null) {
    if (!CODE_RE.test(m[1]) || !ownNamespaces[m[1].split("/")[0]]) continue;
    if (!COMPARED_NOT_BUILT.test(text.slice(0, m.index))) continue;
    if (_rethrowsAt(masked, catches, m.index)) out[m[1]] = true;
  }
  return out;
}

// Every `catch (binding) { ... }` in the text, as { start, end, binding } over
// the brace-matched body, so a position can be asked which catch encloses it.
function _catchRanges(masked) {
  var ranges = [];
  var re = /catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{/g;
  var m;
  while ((m = re.exec(masked)) !== null) {
    var open = m.index + m[0].length - 1;
    var body = bracedBodyAt(masked, open);
    if (body === null) continue;
    ranges.push({ start: open, end: open + 1 + body.length, binding: m[1] });
  }
  return ranges;
}

// Does the code compared at `at` reach the caller? `throw` of the binding
// itself is what leaves it reaching them; a throw of something else has
// translated it, and a catch that throws nothing has consumed it.
//
// The question is per-BRANCH, not per-catch. One catch routinely answers it
// both ways: `lib/backup/index.js` returns on `objectstore/not-found` and
// re-raises everything else, and reading the whole catch demanded a code its
// caller can never receive. Eleven catches in lib/ are that shape, against the
// four `auth-ciba` codes that fall through to the catch's own `throw err`.
function _rethrowsAt(masked, catches, at) {
  var innermost = null;
  for (var i = 0; i < catches.length; i += 1) {
    var c = catches[i];
    if (at < c.start || at > c.end) continue;
    if (innermost === null || c.start > innermost.start) innermost = c;
  }
  if (innermost === null) return false;
  var rethrow = new RegExp("\\bthrow\\s+" + innermost.binding + "\\s*;");
  if (!rethrow.test(masked.slice(innermost.start, innermost.end))) return false;
  var branch = _branchConsequentAt(masked, at);
  // A shape the branch scan cannot read keeps the catch-level answer, which
  // demands the code. An over-demand is a visible failure an author can judge;
  // dropping the code is the silent gap this rule exists to close.
  if (branch === null) return true;
  if (rethrow.test(branch)) return true;
  if (/\breturn\b/.test(branch)) return false;
  if (/\bthrow\b/.test(branch)) return false;
  return true;
}

// The text that runs when the comparison at `at` is true: the consequent of the
// nearest enclosing `if`, whose condition holds the compared literal. Returns
// null when `at` is not in an `if` condition at all, which is a shape this scan
// does not read.
function _branchConsequentAt(masked, at) {
  var i = at;
  while (i >= 0) {
    var open = _unmatchedParenBefore(masked, i);
    if (open === null) return null;
    if (/\bif\s*$/.test(masked.slice(Math.max(0, open - 40), open))) {
      return _consequentAfterCondition(masked, open);
    }
    i = open - 1;
  }
  return null;
}

// The nearest `(` to the left of `at` that `at` sits inside. A brace first means
// the statement opened without one, so `at` is not in a condition: scanning on
// would reach the `(` of the enclosing `catch` or `function` and read its body
// as a branch.
function _unmatchedParenBefore(masked, at) {
  var depth = 0;
  for (var i = at; i >= 0; i -= 1) {
    var c = masked[i];
    if (c === ")") depth += 1;
    else if (c === "(") { if (depth === 0) return i; depth -= 1; }
    else if (c === "{" || c === "}" || c === ";") return null;
  }
  return null;
}

// The statement after the condition that opens at `open`: a braced block, or a
// single statement up to its semicolon.
function _consequentAfterCondition(masked, open) {
  var depth = 0;
  var i = open;
  for (; i < masked.length; i += 1) {
    if (masked[i] === "(") depth += 1;
    else if (masked[i] === ")") { depth -= 1; if (depth === 0) { i += 1; break; } }
  }
  while (i < masked.length && /\s/.test(masked[i])) i += 1;
  if (masked[i] === "{") return bracedBodyAt(masked, i);
  var end = masked.indexOf(";", i);
  return end === -1 ? null : masked.slice(i, end + 1);
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

// A block names a code in whatever span its author reached for. Reading only
// backticks meant a block that wrote "auth-ciba/slow_down" in double quotes
// extracted no codes at all, and a block that names none is SKIPPED, so the
// gate reported clean over a block it had never judged —
// `b.auth.ciba.client.pollToken` named two of its codes that way and omitted
// `auth-ciba/no-auth-req-id`. Double and single quotes count the same as a
// backtick here; a quoted span is how the surrounding prose writes a code.
var QUOTED_SPAN_RE = /`([^`\n]{1,160})`|"([^"\n]{1,160})"|'([^'\n]{1,160})'/g;

// The block's prose: everything before its first multi-line tag. The comment
// convention puts single-line tags first, then prose, then `@opts` / `@example`
// and the rest last, so cutting at the first of those leaves the part where the
// block is describing the primitive rather than illustrating it.
var FIRST_MULTILINE_TAG_RE = /@(?:opts|example|exampleFile|intro|card|section)\b/;

function _proseOf(blk) {
  var at = blk.search(FIRST_MULTILINE_TAG_RE);
  return at === -1 ? blk : blk.slice(0, at);
}
// The suffix allows an underscore because six codes carry one: `auth-ciba`
// re-raises the CIBA and OAuth wire names, `authorization_pending`,
// `slow_down`, `access_denied`, `expired_token`, `invalid_grant` and
// `transaction_failed`, which are the RFC's own spellings and not ours to
// change. Without it the match stopped at the underscore, so
// `auth-ciba/authorization_pending` read as `auth-ciba/authorization`, matched
// no real code, and was dropped — the gate could not see those six anywhere,
// in a backtick or in prose.
var CODE_IN_TEXT_RE = /([a-z0-9][A-Za-z0-9-]*(?:\/[A-Za-z0-9_-]+){1,3})/g;
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
var OPENS_A_FUNCTION = /^\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)/;

// A block is not always adjacent to the function it describes: a module-local
// helper can sit between them, and reading the first function after the block
// then attributes that helper's codes to the wrong primitive. The block for
// `b.mail.server.jmap.emailBodyProperties` is followed by
// `_refusePositiveIntegerOpt`, whose `mail-server-jmap/bad-concurrency` belongs
// to `jmap.create`. So the function NAMED by the block is preferred, and the
// adjacent one is used only when the file declares no function of that name,
// which is the ordinary case for a primitive exported under another name.
var relocatedBodies = 0;

function bodyAfter(code, blockEnd, prim) {
  var after = code.slice(blockEnd);
  var adjacent = after.match(OPENS_A_FUNCTION);
  var segment = String(prim || "").split(".").pop();
  // A block on a factory method is not adjacent to its function at all: in
  // `lib/auth/ciba.js` the `pollToken` block is followed by two unrelated
  // declarations and the method itself is `  async function pollToken(`, sixty
  // lines down and indented. The old lookup gave up as soon as the ADJACENT
  // match failed, and its named fallback anchored at column 0, so seven blocks
  // that name a code were never compared against anything and the gate
  // reported clean over them.
  if (!adjacent || (segment && adjacent[1] !== segment)) {
    var relocated = segment ? _namedFunctionBody(after, segment) : null;
    if (relocated !== null) { relocatedBodies += 1; return relocated; }
    if (!adjacent) return null;
  }
  var end = after.search(/\n\}/);
  return end === -1 ? after : after.slice(0, end);
}

// The body of `function <name>(` wherever it sits and at whatever indentation,
// delimited by matching its own braces rather than by the next closing brace at
// column 0 — an indented declaration's brace is indented too, and stopping at
// the first one would have truncated the body at its first `if`.
function _namedFunctionBody(after, segment) {
  var at = after.search(
    new RegExp("^[ \\t]*(?:async\\s+)?function\\s+" + segment + "\\s*\\(", "m"));
  if (at === -1) return null;
  var masked = maskLiteralsAndComments(after);
  var open = masked.indexOf("{", at);
  if (open === -1) return null;
  var body = bracedBodyAt(masked, open);
  if (body === null) return null;
  // From the declaration, not from inside the brace: every consumer downstream
  // expects the text it is handed to still contain the opening `{` of the
  // function it describes, and `nestedFunctionSpans` returns null without one.
  return after.slice(at, open + 1 + body.length);
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
// A callback handed to one of these runs DURING the call, so a throw inside it
// reaches the primitive's caller and the body must stay in scope. That is the
// opposite of a returned handle or a registered listener, whose throws happen
// later and belong to whoever runs them: `_verifyTrustChain` raises
// `mail-crypto/smime/bad-chain-cert` and `mail-crypto/smime/bad-trust-anchor`
// inside `Array.map` callbacks, and stripping those hid both from
// `b.mail.crypto.smime.verifyAll`.
// Which call a callback was handed to decides whether its throws reach THIS
// caller. Listing the synchronous ones was the wrong way round: the list has to
// grow for every API anyone uses, and four separate holes were found in it, one
// per review round. `new Promise`'s executor runs during the call, a `.then` or
// `.catch` callback rejects the promise the caller awaits, and a comparator or a
// replacer handed to any other function runs before that function returns.
//
// The constructs that genuinely defer are few and they do not grow: a listener
// registration, a timer, and a microtask. So those are named, and everything
// else is treated as running into this caller.
var DEFERRING_CALL = new RegExp(
  "(?:\\.(?:on|once|addListener|prependListener|addEventListener|subscribe)" +
  "|\\bset(?:Timeout|Interval|Immediate)|\\bqueueMicrotask|\\bprocess\\.nextTick)" +
  "\\s*\\((?:[^()]*,\\s*)?$");
var SYNCHRONOUS_CALLBACK_METHODS = new RegExp(
  "(?:new\\s+Promise|[A-Za-z_$][\\w$]*)\\s*\\((?:[^()]*,\\s*)?$");

// Is the function body opening at `at` the body of a callback passed straight to
// one of those methods? Walks back over the parameter list and the `function`
// keyword or arrow to reach the start of the function expression, then asks what
// call it sits in.
function isSynchronousCallback(masked, at, fileMasked) {
  var i = skipBackWhitespace(masked, at - 1);
  if (i < 0) return false;
  if (masked[i] === ">" && masked[i - 1] === "=") {
    i = skipBackWhitespace(masked, i - 2);
  } else if (masked[i] === ")") {
    var depth = 0;
    while (i >= 0) {
      if (masked[i] === ")") depth += 1;
      else if (masked[i] === "(") { depth -= 1; if (depth === 0) break; }
      i -= 1;
    }
    if (i < 0) return false;
    i = skipBackWhitespace(masked, i - 1);
    var end = i;
    while (i >= 0 && /[A-Za-z0-9_$]/.test(masked[i])) i -= 1;
    if (i !== end && masked.slice(i + 1, end + 1) !== "function") {
      // A shorthand method or a named reference, not an inline callback.
      return false;
    }
    if (i !== end) i = skipBackWhitespace(masked, i);
  } else {
    return false;
  }
  if (i < 0) return false;
  // A callback does not have to be a bare argument. `_readSyncCore` hands
  // `fdSafeReadSync` an options object carrying `errorFor`, which that helper
  // calls while it runs, so its `atomic-file/short-read` reaches the caller of
  // `b.atomicFile.read`. Reading only a bare argument stripped that body and
  // let the block omit the code while this gate still reported clean. So when
  // the function is a property VALUE, step out of the object literal and ask
  // the same question of the call the object itself was handed to.
  var stepped = stepOutOfPropertyPosition(masked, i);
  if (stepped.at < 0) return false;
  var before = masked.slice(0, stepped.at + 1);
  if (DEFERRING_CALL.test(before)) return false;
  if (!SYNCHRONOUS_CALLBACK_METHODS.test(before)) return false;
  // A bare argument runs during the call. A property VALUE only runs if the
  // callee calls it, and a callee in this codebase that takes an object of
  // functions is as often a builder storing them on the handle it returns:
  // `_baseSchema({ run: ... })` keeps `run` for `parse` to call later, while
  // `fdSafeReadSync(path, { errorFor: ... })` calls `errorFor` while it reads.
  // So the question is asked of the callee's own body, and a callee this file
  // does not declare is read as calling it, which is the fail-closed answer.
  if (stepped.key !== null &&
      !calleeInvokesKey(fileMasked || masked, before, stepped.key)) return false;
  return true;
}

var PROPERTY_KEY_BEFORE = /(?:([A-Za-z_$][\w$]*)|"([^"]*)"|'([^']*)')\s*:\s*$/;

// At `i` sits the last character before a function expression. If that is a
// property key, walk out to the character before the object literal's `{`, so
// the caller's call test reads the call the object was passed to. Answers the
// outermost key it stepped past, or null when the function was not in property
// position; `at` is -1 when the object literal is not closed in this text.
function stepOutOfPropertyPosition(masked, i) {
  var key = null;
  var guard = 0;
  for (;;) {
    var m = PROPERTY_KEY_BEFORE.exec(masked.slice(0, i + 1));
    if (!m || guard >= 8) break;
    guard += 1;
    key = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    var depth = 0;
    var j = i;
    while (j >= 0) {
      if (masked[j] === "}") depth += 1;
      else if (masked[j] === "{") { if (depth === 0) break; depth -= 1; }
      j -= 1;
    }
    if (j < 0) return { at: -1, key: key };
    i = skipBackWhitespace(masked, j - 1);
  }
  return { at: i, key: key };
}

// `before` ends at the `(` of the call the object literal was handed to, with
// any earlier arguments still in it. Read the callee's name and which parameter
// receives the object.
var CALLEE_AND_ARGS = /([A-Za-z_$][\w$]*)\s*\(([^()]*)$/;

// Does the function named in `before` call `key` on the object it was passed?
// Reads the callee's declaration in this same file: the parameter the object
// arrives on, then that parameter's `.key(`, an alias of it that is called, or
// a bare `key(` from a destructured parameter. A callee this file does not
// declare answers true.
function calleeInvokesKey(masked, before, key) {
  var call = CALLEE_AND_ARGS.exec(before);
  if (!call) return true;
  var argIndex = call[2].split(",").length - 1;
  var decl = new RegExp("\\bfunction\\s+" + escapeRegExp(call[1]) +
    "\\s*\\(([^)]*)\\)\\s*\\{");
  var found = decl.exec(masked);
  if (!found) return true;
  var body = bracedBodyAt(masked, found.index + found[0].length - 1);
  if (body === null) return true;
  var params = found[1].split(",").map(function (p) { return p.trim(); });
  var param = params[argIndex] || "";
  var k = escapeRegExp(key);
  if (new RegExp("\\b" + k + "\\s*\\(").test(body)) return true;
  if (!/^[A-Za-z_$][\w$]*$/.test(param)) return true;
  var p = escapeRegExp(param);
  if (new RegExp("\\b" + p + "\\s*(?:\\.\\s*" + k + "|\\[\\s*[\"']" + k + "[\"']\\s*\\])\\s*\\(")
      .test(body)) return true;
  var alias = new RegExp("(?:var|let|const)\\s+([A-Za-z_$][\\w$]*)\\s*=[^;]*\\b" + p +
    "\\s*(?:\\.\\s*" + k + "|\\[\\s*[\"']" + k + "[\"']\\s*\\])").exec(body);
  if (alias && new RegExp("\\b" + escapeRegExp(alias[1]) + "\\s*\\(").test(body)) return true;
  return false;
}

function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// The text between the brace at `open` and its match, or null when unbalanced.
// Not `bodyAfter`, which takes a block end and finds the function below it.
function bracedBodyAt(masked, open) {
  var depth = 0;
  for (var i = open; i < masked.length; i += 1) {
    if (masked[i] === "{") depth += 1;
    else if (masked[i] === "}") { depth -= 1; if (depth === 0) return masked.slice(open + 1, i); }
  }
  return null;
}

// Which nested bodies RUN while the primitive runs.
//
// "Called somewhere in the body" is the wrong question, and asking it credited a
// factory with the codes of the handle it returns: `lib/restore.js` declares
// `inspect`, which throws `restore/bundle-not-found`, and `run` calls it, but both
// are methods on the returned object, so neither runs during `create`. The
// question is reachability from the statements that actually execute.
//
// So: take the body with every nested body removed, which is what runs. A nested
// function named there runs too, and so does one named inside a body already
// kept, transitively. Everything else runs later, if ever.
//
// `b.mail.deploy.autoConfigXml` reaches `_server` this way, which is how its
// `mail-deploy/bad-port` becomes part of its contract, while `b.restore.create`
// reaches none of its handle's methods.
function reachableNestedBodies(masked, nested) {
  // Blank the declaration HEADER as well as the body. Leaving the header behind
  // made `function inspect(bundleId)` read as a call to `inspect`, so every
  // nested declaration looked reachable and the factory was credited with its
  // handle's codes again.
  var immediate = masked.split("");
  nested.forEach(function (n) {
    for (var i = n.headStart; i < n.end && i < immediate.length; i += 1) {
      if (immediate[i] !== "\n") immediate[i] = " ";
    }
  });
  var byName = {};
  nested.forEach(function (n) { if (n.name) byName[n.name] = n; });

  // A helper bound to a second name is still that helper, so calling it through
  // the alias reaches its body. `var write = _writeRow;` then `write(row)`.
  var aliasRe = /(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;,\n]/g;
  var am;
  while ((am = aliasRe.exec(masked)) !== null) {
    if (byName[am[2]] && !byName[am[1]]) byName[am[1]] = byName[am[2]];
  }

  function callsIn(text) {
    var out = [];
    Object.keys(byName).forEach(function (name) {
      var re = new RegExp("(?:^|[^.\\w$])" + name.replace(/\$/g, "\\$") + "\\s*\\(");
      if (re.test(text)) out.push(name);
    });
    return out;
  }

  var keep = {};
  var frontier = callsIn(immediate.join(""));
  while (frontier.length) {
    var next = [];
    frontier.forEach(function (name) {
      if (keep[name] || !byName[name]) return;
      keep[name] = true;
      var n = byName[name];
      callsIn(masked.slice(n.brace, n.end)).forEach(function (c) {
        if (!keep[c]) next.push(c);
      });
    });
    frontier = next;
  }
  return keep;
}

// Every outermost nested function body, with the name it is declared under.
function nestedDeclarations(masked, from) {
  var out = [];
  var depth = 0;
  var start = -1;
  for (var i = from; i < masked.length; i += 1) {
    var c = masked[i];
    if (c === "{") {
      depth += 1;
      if (start === -1 && opensFunctionBody(masked, i)) {
        start = i;
        var decl = nameOfBodyAt(masked, i);
        out.push({
          brace: i, end: -1, depth: depth,
          name: decl.name, headStart: decl.headStart,
        });
      }
    } else if (c === "}") {
      if (start !== -1 && out.length && out[out.length - 1].end === -1 &&
          depth === out[out.length - 1].depth) {
        out[out.length - 1].end = i + 1;
        start = -1;
      }
      depth -= 1;
      if (depth < 0) return null;
    }
  }
  if (depth !== 0 || start !== -1) return null;
  return out;
}

// The name a nested body is declared under, for `function name(...) {`,
// `var name = function (...) {`, `var name = (...) => {` and the shorthand
// method form. An anonymous callback has none.
function nameOfBodyAt(masked, braceIndex) {
  var from = Math.max(0, braceIndex - 220);
  var head = masked.slice(from, braceIndex);
  var m = /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*$/.exec(head);
  if (m) return { name: m[1], headStart: from + m.index };
  m = /(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b[^(]*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*$/.exec(head);
  if (m) return { name: m[1], headStart: from + m.index };
  // A helper hung on an object, either as a property of a literal or assigned
  // onto one. Reading only `function name` and `var name =` missed both, so a
  // helper the body calls through its object was stripped with the deferred ones.
  m = /(?:^|[,{;]\s*)([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\b[^(]*\([^)]*\)|\([^)]*\)\s*=>)\s*$/.exec(head);
  if (m) return { name: m[1], headStart: from + m.index };
  m = /\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b[^(]*\([^)]*\)|\([^)]*\)\s*=>)\s*$/.exec(head);
  if (m) return { name: m[1], headStart: from + m.index };
  return { name: null, headStart: braceIndex };
}

// `fileSource` is the whole file this body came from, which is where a callee
// taking an object of functions is declared. Without it a property-position
// callback is read as running during the call, which is the fail-closed answer
// the fixtures below expect.
function nestedFunctionSpans(body, fileSource) {
  var masked = maskLiteralsAndComments(body);
  var fileMasked = fileSource === undefined
    ? masked : maskLiteralsAndComments(fileSource);
  var declEnd = masked.search(/\{/);
  if (declEnd === -1) return null;
  var nested = nestedDeclarations(masked, declEnd + 1);
  if (nested === null) return null;
  if (nested.some(function (n) { return n.end === -1; })) return null;
  var keep = reachableNestedBodies(masked, nested);
  var spans = [];
  nested.forEach(function (n) {
    if (n.name && keep[n.name]) return;
    if (isSynchronousCallback(masked, n.brace, fileMasked)) return;
    spans.push([n.brace, n.end]);
  });
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

// Every top-level function the module declares, keyed by name, each already
// narrowed to its own code. A primitive that calls one of these synchronously
// raises whatever it raises, so those codes belong to the primitive's contract:
// `b.archive.unwrap` reaches `_tenantKey`, which throws
// `archive-wrap/no-tenant-id`, and reading one lexical body never saw it.
//
// A body the brace scan cannot read is counted rather than skipped silently, so
// the coverage this cannot follow stays visible.
var unreadableHelpers = 0;

function localHelpers(code) {
  var out = {};
  var re = /^(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/gm;
  var m;
  while ((m = re.exec(code)) !== null) {
    var rest = code.slice(m.index);
    var end = rest.search(/\n\}/);
    var body = end === -1 ? rest : rest.slice(0, end);
    var spans = nestedFunctionSpans(body, code);
    if (spans === null) { unreadableHelpers += 1; continue; }
    out[m[1]] = spans.length ? withoutSpans(body, spans) : body;
  }
  return out;
}

// Call detection reads a body whose strings and comments are MASKED. Without
// that, `_requireInit`'s message "db.init() must be awaited" matches `init(` and
// drags the whole init function in, which demanded `db/bad-at-rest` of
// `b.db.stream` — a code that primitive does not throw.
function bodiesReachedFrom(startBody, helpers) {
  var names = Object.keys(helpers);
  var seen = {};
  var reached = [startBody];
  var frontier = [startBody];
  while (frontier.length) {
    var next = [];
    frontier.forEach(function (body) {
      var callable = maskLiteralsAndComments(body);
      names.forEach(function (nm) {
        if (seen[nm]) return;
        // A MEMBER call is somebody else's function. `\b` is satisfied between
        // the dot and the name, so a bare word boundary let `JSON.parse(` match a
        // local helper called `parse` and drag its codes in.
        if (!new RegExp("(?<![.\\w$])" + nm + "\\s*\\(").test(callable)) return;
        seen[nm] = true;
        reached.push(helpers[nm]);
        next.push(helpers[nm]);
      });
    });
    frontier = next;
  }
  return reached;
}

// ---- The vocabulary: namespaces the tree really builds errors in. ----
var NAMESPACES = {};
var STRIPPED = {};
var OWN_NAMESPACES = {};
var LOCAL_HELPERS = {};
var COMPOSED_BY_ALIAS = {};
var BUILDER_SUFFIXES = builderSuffixes(
  stripBlocks(nodeFs.readFileSync(nodePath.join(LIB, "gate-contract.js"), "utf8")));
FILES.forEach(function (full) {
  var rel = nodePath.relative(ROOT, full).replace(/\\/g, "/");
  var code = stripBlocks(nodeFs.readFileSync(full, "utf8"));
  STRIPPED[rel] = code;
  OWN_NAMESPACES[rel] = namespacesIn(code);
  LOCAL_HELPERS[rel] = localHelpers(code);
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

      // A code counts as documented wherever it is written inside a backticked
      // span, not only when the whole span is the bare code. `b.vault` writes
      // `VaultError("vault/not-initialized")`, which names the code an operator
      // would grep for; reading only whole spans called that undocumented.
      var documented = {};
      var bm;
      // Backticks are read across the whole block: a backtick is this
      // codebase's way of naming an identifier wherever it appears. A QUOTE is
      // ordinary punctuation, and `@opts` and `@example` are full of quoted
      // profile names, sample inputs and illustrated outputs, so a quoted code
      // counts only where the block is making a prose claim. Reading quotes
      // everywhere turned one `// → "message-id/unbracketed"` in an example
      // into a claim that the block enumerates all nine of that guard's codes.
      var quotable = _proseOf(blk);
      QUOTED_SPAN_RE.lastIndex = 0;
      while ((bm = QUOTED_SPAN_RE.exec(blk)) !== null) {
        var inner = bm[1] !== undefined ? bm[1] : null;
        if (inner === null) {
          var quoted = bm[2] !== undefined ? bm[2] : bm[3];
          if (quotable.indexOf(quoted) === -1) continue;
          inner = quoted;
        }
        var cm;
        CODE_IN_TEXT_RE.lastIndex = 0;
        while ((cm = CODE_IN_TEXT_RE.exec(inner)) !== null) {
          if (!CODE_RE.test(cm[1])) continue;
          if (!NAMESPACES[cm[1].split("/")[0]]) continue;
          documented[cm[1]] = true;
        }
      }
      if (Object.keys(documented).length === 0) continue;

      var prim = (blk.match(/@primitive\s+(\S+)/) || [])[1] || "(unnamed)";
      var body = bodyAfter(code, m.index + blk.length, prim);
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
      var spans = nestedFunctionSpans(body, src);
      if (spans === null) { heldBack.push(entry); continue; }
      var own = body;
      if (spans.length) {
        own = withoutSpans(body, spans);
        narrowed += 1;
      }
      // A code the primitive's own body COMPARES against is one it handles, so a
      // helper raising it does not raise it into the caller:
      // `b.network.dns.discoverEncrypted` catches `dns/no-result` from the SVCB
      // query and throws `dns/ddr-not-discovered` instead, and demanding the
      // caught code would put a failure in the documentation that an operator can
      // never receive. Only PROPAGATION is suppressed, not construction: a
      // primitive that compares a code and also builds it still documents it.
      var handled = comparedCodesIn(own, OWN_NAMESPACES[rel]);

      // The codes of every body this one reaches, not only its own. A helper the
      // primitive calls synchronously raises into the caller, so its codes are
      // part of the primitive's contract.
      var allHelpers = Object.assign({}, LOCAL_HELPERS[rel], nestedHelperBodies(body));
      var raisers = raisingHelperNames(allHelpers);
      var deferrers = deferringHelperNames(allHelpers);
      var thrown = codesRaisedIn(own, OWN_NAMESPACES[rel], raisers, deferrers);
      var reached = bodiesReachedFrom(own, LOCAL_HELPERS[rel]);
      reached.forEach(function (b, idx) {
        if (idx > 0) {
          Object.keys(codesRaisedIn(b, OWN_NAMESPACES[rel], raisers, deferrers)).forEach(function (c) {
            if (!handled[c]) thrown[c] = true;
          });
        }
        Object.keys(COMPOSED_BY_ALIAS[rel]).forEach(function (alias) {
          if (!new RegExp("\\b" + alias + "\\s*\\(").test(b)) return;
          COMPOSED_BY_ALIAS[rel][alias].forEach(function (c) {
            if (idx === 0 || !handled[c]) thrown[c] = true;
          });
        });
      });
      // A code this body recognised in a catch and then re-raised reaches the
      // caller through it, so it is demanded even though nothing here builds it.
      Object.keys(rethrownComparedCodesIn(own, OWN_NAMESPACES[rel]))
        .forEach(function (c) { thrown[c] = true; });

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

  // A helper whose body the brace scan cannot read is not followed, so its codes
  // are not demanded of the primitives that call it. That is the conservative
  // direction, and it is reported rather than silent: a change that made most
  // helpers unreadable would quietly shrink what this gate checks.
  var helperCount = Object.keys(LOCAL_HELPERS).reduce(function (n, rel) {
    return n + Object.keys(LOCAL_HELPERS[rel]).length;
  }, 0);
  check("the helper call graph is readable, so codes raised through one are followed",
        helperCount > unreadableHelpers * 4,
        helperCount + " helpers followed, " + unreadableHelpers + " unreadable");

  // Blocks whose function is not the one immediately below them, reported so the
  // relocation stays visible: before it, a module-local helper sitting between a
  // block and its function had its codes read as that primitive's.
  check("a block separated from its function by a helper is still matched to it",
        relocatedBodies > 0,
        relocatedBodies + " blocks read a function further down the file");

  // A block on a factory method is the harder shape: nothing resembling a
  // function follows it, and the method is indented. Giving up when the
  // ADJACENT match failed left seven such blocks compared against nothing,
  // `b.auth.ciba.client.pollToken` among them, so the gate reported clean over
  // a block that named two of its codes and omitted a third.
  var factoryFixture = [
    "/**",
    " * @primitive b.fixture.client.pollThing",
    " * Throws `fixture/documented` when the ticket is empty.",
    " */",
    "  var _unrelated = new Map();",
    "",
    "  function _alsoUnrelated(x) { return x; }",
    "",
    "  async function pollThing(popts) {",
    "    if (!popts.ticket) {",
    "      throw new FixtureError(\"fixture/documented\", \"ticket required\");",
    "    }",
    "    if (popts.late) {",
    "      throw new FixtureError(\"fixture/undocumented\", \"too late\");",
    "    }",
    "    return null;",
    "  }",
    "",
    "  return { pollThing: pollThing };",
  ].join("\n");
  var blockEnd = factoryFixture.indexOf("*/") + 2;
  var factoryBody = bodyAfter(factoryFixture, blockEnd, "b.fixture.client.pollThing");
  check("a block on a factory method finds its indented function further down",
        factoryBody !== null && factoryBody.indexOf("fixture/documented") !== -1,
        factoryBody === null ? "null" : JSON.stringify(factoryBody.slice(0, 60)));
  check("and the body stops at that function rather than running to the factory's end",
        factoryBody !== null && factoryBody.indexOf("return { pollThing") === -1 &&
        factoryBody.indexOf("_alsoUnrelated") === -1,
        factoryBody === null ? "null" : JSON.stringify(factoryBody.slice(-60)));
  var factoryCodes = Object.keys(codesIn(factoryBody || "", { fixture: true })).sort();
  check("so both of its codes are read, not just the first",
        factoryCodes.join(",") === "fixture/documented,fixture/undocumented",
        factoryCodes.join(","));
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
  // The control for the span scan, pinning both directions. The outer function's
  // own throw must survive the narrowing. A function it RETURNS runs later, when
  // the caller invokes the handle, so that body comes out. A callback handed to
  // `Array.map` runs DURING the call, so its throw reaches the same caller and
  // that body stays. A scan that stripped everything, or nothing, fails one of
  // these.
  var body = [
    "function outer(x) {",
    "  if (!x) throw new FixtureError(\"fixture/outer-throw\", \"empty\");",
    "  x.map(function (item) {",
    "    if (!item) throw new FixtureError(\"fixture/sync-callback\", \"empty item\");",
    "    return item;",
    "  });",
    "  return function handle(y) {",
    "    if (!y) throw new FixtureError(\"fixture/deferred\", \"later\");",
    "    return y;",
    "  };",
  ].join("\n");
  var spans = nestedFunctionSpans(body);
  check("the brace scan reads the body and strips only the deferred function",
        spans !== null && spans.length === 1,
        spans === null ? "null" : spans.length + " spans");
  var own = withoutSpans(body, spans || []);
  var codes = Object.keys(codesIn(own, { fixture: true })).sort();
  check("the outer function's own code survives the narrowing",
        codes.indexOf("fixture/outer-throw") !== -1, codes.join(","));
  check("a synchronous callback's code survives too, because it raises into the " +
        "same caller",
        codes.indexOf("fixture/sync-callback") !== -1, codes.join(","));
  check("the returned handle's code does not, because it runs later",
        codes.indexOf("fixture/deferred") === -1, codes.join(","));

  // A brace inside a string or a comment must not move the counter, and an
  // unbalanced body must come back null rather than a confident wrong span.
  var tricky = [
    "function outer(x) {",
    "  var open = \"{\";",
    "  // a comment with a } in it",
    "  return function (i) { return i + \"}\"; };",
  ].join("\n");
  var trickySpans = nestedFunctionSpans(tricky);
  check("a brace inside a string or a comment does not skew the scan",
        trickySpans !== null && trickySpans.length === 1,
        trickySpans === null ? "null" : trickySpans.length + " spans");
  check("an unreadable body comes back null, so the block is held back whole",
        nestedFunctionSpans("function outer() {\n  foo(function () {\n") === null);

  // A callback in property position runs during the call only if the callee
  // calls it. `_readSyncCore` hands `fdSafeReadSync` an `errorFor` that it
  // calls while reading, so its codes are the caller's; `_tupleWithRest` hands
  // `_baseSchema` a `run` it keeps for the handle, so its codes are not.
  var callsIt = [
    "function reader(path, opts) {",
    "  var errorFor = opts.errorFor || null;",
    "  if (errorFor) throw errorFor(\"enoent\", {});",
    "  return null;",
    "}",
    "function outer(p) {",
    "  return reader(p, {",
    "    errorFor: function (kind) {",
    "      return new FixtureError(\"fixture/in-called-option\", kind);",
    "    },",
    "  });",
  ].join("\n");
  var callsSpans = nestedFunctionSpans(callsIt.slice(callsIt.indexOf("function outer")), callsIt);
  check("a property callback the callee calls is kept in scope",
        callsSpans !== null && callsSpans.length === 0,
        callsSpans === null ? "null" : callsSpans.length + " spans");

  var storesIt = [
    "function build(spec) {",
    "  return { _run: spec.run, kind: spec.kind };",
    "}",
    "function outer(items) {",
    "  return build({",
    "    kind: \"tuple\",",
    "    run: function (value) {",
    "      return new FixtureError(\"fixture/in-stored-option\", value);",
    "    },",
    "  });",
  ].join("\n");
  var storesSpans = nestedFunctionSpans(storesIt.slice(storesIt.indexOf("function outer")), storesIt);
  check("a property callback the callee only stores is stripped",
        storesSpans !== null && storesSpans.length === 1,
        storesSpans === null ? "null" : storesSpans.length + " spans");

  // Without the file, the callee cannot be read, and the fail-closed answer is
  // that it runs: a gate that guessed "stored" here would drop real codes.
  var blindSpans = nestedFunctionSpans(storesIt.slice(storesIt.indexOf("function outer")));
  check("with no file to read the callee in, a property callback is kept",
        blindSpans !== null && blindSpans.length === 0,
        blindSpans === null ? "null" : blindSpans.length + " spans");
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

  // A code names an option as the option is spelled, so the grammar has to admit
  // the option's own case. Reading lowercase only made `mail-deploy/bad-displayName`
  // invisible, and the block that omitted it passed.
  check("a code that names an option keeps the option's spelling",
        CODE_RE.test("mail-deploy/bad-displayName") &&
        CODE_RE.test("deliver/bad-timeout-mxLookupMs") &&
        CODE_RE.test("vex/missing-documentId") &&
        !CODE_RE.test("Content-Type"));

  // Which nested bodies count. A helper the body CALLS runs during the call, so
  // its throws are the caller's contract; one reached only from a method on the
  // returned object runs later, if ever. Stripping every nested body hid the
  // first, and keeping every body that is called anywhere credited a factory with
  // the second.
  var nestedFixture = [
    "function factory(opts) {",
    "  function _now(v) {",
    "    if (!v) throw new FixtureError(\"fixture/from-helper\", \"no v\");",
    "    return v;",
    "  }",
    "  function _later(v) {",
    "    if (!v) throw new FixtureError(\"fixture/from-handle\", \"no v\");",
    "  }",
    "  var ready = _now(opts.v);",
    "  return { use: function (x) { _later(x); return ready; } };",
  ].join("\n");   // no closing brace: bodyAfter cuts the body at the first `\n}`
  var nestedSpans = nestedFunctionSpans(nestedFixture);
  var nestedCodes = nestedSpans === null ? ["<unreadable>"] :
    Object.keys(codesRaisedIn(withoutSpans(nestedFixture, nestedSpans), own)).sort();
  check("a nested helper the body calls is part of the contract, and one reached " +
        "only from a returned method is not",
        nestedCodes.join(",") === "fixture/from-helper", nestedCodes.join(","));

  // Which argument positions RAISE a code, since being an argument is not enough.
  // A validator carrying an error class raises it, and so does a local helper
  // whose body throws. An audit event's `reason` reports a code, and an error
  // handed to a callback is raised by whatever that callback rejects, not here.
  var raiseFixture = [
    "function only(x) {",
    "  validateOpts.checkOrThrow(x, [\"a\"], \"only\", FixtureError, \"fixture/via-validator\");",
    "  _fail(\"nope\", \"fixture/via-throwing-helper\");",
    "  _emitAudit(\"only.failed\", \"failure\", { reason: \"fixture/reported-only\" });",
    "  _finishTask(slot, true, new FixtureError(\"fixture/handed-off\", \"later\"));",
    "  report(new FixtureError(\"fixture/via-callback\", \"thrown by the caller's hook\"));",
    "  var e = new FixtureError(\"fixture/assigned-then-thrown\", \"decorated\");",
    "  e.meta = { at: x };",
    "  if (x.bad) throw e;",
    "  if (x.wrapped) return new FixtureError(\"fixture/returned\", \"for a caller\");",
    "  if (!x) throw new FixtureError(\"fixture/thrown\", \"empty\");",
  ].join("\n");
  var raiseHelpers = {
    _fail:       "function _fail(m, c) { throw new FixtureError(c, m); }",
    _emitAudit:  "function _emitAudit(a, o, meta) { audit.safeEmit({ action: a }); }",
    // Takes an error and settles a promise it holds, so it raises into whoever
    // holds that promise rather than into this caller.
    _finishTask: "function _finishTask(slot, failed, err) { slot.reject(err); }",
  };
  var raised = Object.keys(codesRaisedIn(raiseFixture, own,
    raisingHelperNames(raiseHelpers), deferringHelperNames(raiseHelpers))).sort();
  check("a code raises from a throw, from an error assigned and thrown later, from " +
        "one returned for a caller to throw, from a validator carrying an error " +
        "class, from a local helper that throws, and from an error handed to a " +
        "callback the scan cannot classify, while an audit reason and an error " +
        "handed to a local helper that only settles a promise do not",
        raised.join(",") ===
          ["fixture/assigned-then-thrown", "fixture/returned", "fixture/thrown",
           "fixture/via-callback", "fixture/via-throwing-helper",
           "fixture/via-validator"].join(","),
        raised.join(","));
  // A literal outside the file's own namespaces is another module's code, named
  // for reference rather than thrown here, so it must not be demanded.
  var foreign = Object.keys(codesIn("throw other.factory(\"other/elsewhere\");", own));
  check("a code in another module's namespace is not counted as thrown here",
        foreign.length === 0, foreign.join(","));

  // What a catch does with a code it compares, in the four shapes one catch
  // mixes. Returning consumes the code and the caller never sees it; throwing
  // another error translates it; `throw err` on the branch, and a branch that
  // falls through to the catch's own `throw err`, both leave the caller holding
  // it. All four read as handled before, which is how `pollToken` stopped
  // having to name `auth-ciba/expired_token` and its three siblings. The
  // underscore matters as much as the branch: the literal pattern stopped a
  // code's suffix at `[A-Za-z0-9-]`, so the six `auth-ciba` codes carrying the
  // RFC's own wire names never matched it in the first place.
  var catchFixture = [
    "async function poll(id) {",
    "  try { return await _post(id); }",
    "  catch (err) {",
    "    if (err.code === \"fixture/not_found\") return null;",
    "    if (err.code === \"fixture/unusable\") throw new FixtureError(\"fixture/translated\", \"x\");",
    "    if (err.code === \"fixture/denied\") { _state.delete(id); throw err; }",
    "    if (err && (err.code === \"fixture/pending\" || err.code === \"fixture/slow_down\")) {",
    "      _state.delete(id);",
    "    }",
    "    throw err;",
    "  }",
    "}",
  ].join("\n");
  var consumed = Object.keys(comparedCodesIn(catchFixture, own)).sort();
  var passedOn = Object.keys(rethrownComparedCodesIn(catchFixture, own)).sort();
  check("a code the catch returns on, and one it translates, are handled",
        consumed.join(",") === "fixture/not_found,fixture/unusable", consumed.join(","));
  check("while one re-raised on its own branch, and one falling through to the " +
        "catch's throw, stay part of the contract",
        passedOn.join(",") === "fixture/denied,fixture/pending,fixture/slow_down",
        passedOn.join(","));
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  var inCode = ANY_OWN_NAMESPACE_LITERAL.exec("(err.code === \"auth-ciba/expired_token\")");
  ANY_OWN_NAMESPACE_LITERAL.lastIndex = 0;
  CODE_IN_TEXT_RE.lastIndex = 0;
  var inProse = CODE_IN_TEXT_RE.exec("raises auth-ciba/expired_token when it ends");
  CODE_IN_TEXT_RE.lastIndex = 0;
  check("a code carrying the wire name's underscore is read by all three " +
        "patterns that describe a code",
        CODE_RE.test("auth-ciba/expired_token") &&
        inCode !== null && inCode[1] === "auth-ciba/expired_token" &&
        inProse !== null && inProse[1] === "auth-ciba/expired_token",
        (inCode === null ? "no literal match" : inCode[1]) + " / " +
        (inProse === null ? "no prose match" : inProse[1]));
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
