// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every `b.<namespace>.<member>` an operator-facing document names resolves
 * against the framework.
 *
 * A name in README.md, SECURITY.md or the compliance crosswalks is an
 * instruction: an operator wires what it says. A name that no longer resolves
 * sends them to an API that is not there, and nothing was checking, so the
 * drift accumulated across releases until a sweep found 44 of them. The ones
 * that were wrong rather than shorthand pointed at a real neighbour:
 * `b.cluster.create` for `init`, `b.session.invalidateAll` for
 * `destroyAllForUser`, `b.mail.crypto.cms` for `smime`,
 * `b.network.dns.doh` for `useDnsOverHttps`, and `b.atoKillSwitch.trigger`
 * for `b.auth.atoKillSwitch.trigger`.
 *
 * Two shapes resolve nowhere and are still correct, so each is listed by name
 * with the reason rather than waved through by a pattern.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var b        = helpers.b;
var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var ROOT = nodePath.join(__dirname, "..", "..");

// A member on the object a namespace's `create()` returns, written in the
// framework's own shorthand. `lib/auth/oauth.js` uses the same spelling in an
// `@related` tag, so this is the house convention and not drift.
var CREATE_HANDLE_SHORTHAND = Object.freeze({
  "b.acme.renewIfDue":                 "b.acme.create().renewIfDue — RFC 9773 ARI renewal check",
  "b.agent.orchestrator.hydrate":      "b.agent.orchestrator.create().hydrate — the facade member, on a namespace that also holds sub-namespaces",
  "b.agent.orchestrator.register":     "b.agent.orchestrator.create().register — the facade member, on a namespace that also holds sub-namespaces",
  "b.auth.oauth.parseCallback":        "b.auth.oauth.create().parseCallback",
  "b.auth.oauth.refreshAccessToken":   "b.auth.oauth.create().refreshAccessToken",
  "b.backup.scheduleTest":             "b.backup.create().scheduleTest",
  "b.cache.set":                       "b.cache.create().set",
  "b.cache.update":                    "b.cache.create().update",
  "b.dualControl.consume":             "b.dualControl.create().consume",
  "b.flag.middleware":                 "b.flag.create().middleware",
  "b.mailStore.appendMessage":         "b.mailStore.create().appendMessage",
  "b.mailStore.createFolder":          "b.mailStore.create().createFolder",
  "b.restore.rollback":                "b.restore.create().rollback — the rollback a restore leaves behind",
});

// Names the prose mentions BECAUSE they are gone. Resolving would mean the
// removal had been undone.
var DELIBERATELY_ABSENT = Object.freeze({
  "b.backup.localStorage": "renamed to b.backup.diskStorage in v0.11.2, alias removed in v0.11.20; " +
                           "the Node 26 localStorage note exists to record that removal",
  "b.backup.X":            "the same note writes the property-access shape `b.backup.X(...)` to " +
                           "contrast it with a bare global; the X stands for any member rather " +
                           "than naming one",
});

// Member names may hold underscores (ml_kem_1024), so a class that stops at
// `_` would report a truncated name that resolves nowhere.
// A name written in prose opens a word: it follows the start of the text,
// whitespace, or a delimiter someone quotes or brackets it with. Matching
// anywhere read the `b.txt` out of the filename `a;b.txt` in an example and
// reported it as a namespace that resolves to nothing.
var OPENS_A_NAME = "(?:^|[\\s`\"'(\\[<>|*,])";

var REFERENCE_RE = new RegExp(
  OPENS_A_NAME + "b\\.([A-Za-z][A-Za-z0-9_]*)((?:\\.[A-Za-z][A-Za-z0-9_]*)+)", "g");

// Sources under lib/ that name primitives to a reader rather than calling
// them: a compliance crosswalk answers an auditor "which primitive covers
// this control", so a name it carries is as operator-facing as one in a
// document, and nothing else resolves it.
var CATALOG_SOURCES = ["nist-crosswalk.js", "compliance-ai-act.js"];

// `b.<name>` with no member after it. Written as its own class because the
// member pattern above needs a dot to match, so a namespace named alone was
// never resolved against anything.
// The `*` exclusion keeps the family globs prose writes, `b.guard*` and
// `b.safe*`, out of it: those name a family rather than a namespace.
var NAMESPACE_RE = new RegExp(
  OPENS_A_NAME + "b\\.([A-Za-z][A-Za-z0-9_]*)(?![A-Za-z0-9_.*])", "g");

function _operatorDocs() {
  var files = [];
  ["README.md", "SECURITY.md", "MIGRATING.md"].forEach(function (name) {
    var p = nodePath.join(ROOT, name);
    if (nodeFs.existsSync(p)) files.push(p);
  });
  var docsDir = nodePath.join(ROOT, "docs");
  if (nodeFs.existsSync(docsDir)) {
    nodeFs.readdirSync(docsDir).forEach(function (name) {
      if (/\.md$/.test(name)) files.push(nodePath.join(docsDir, name));
    });
  }
  // The compliance crosswalks name primitives to an auditor the same way a
  // document does, and they are read by `b.nistCrosswalk` rather than by a
  // person, so nothing else checks them. A rename applied to one of three
  // entries left the other two naming a primitive that does not exist.
  CATALOG_SOURCES.forEach(function (name) {
    var p = nodePath.join(ROOT, "lib", name);
    if (nodeFs.existsSync(p)) files.push(p);
  });
  // The release notes being written now. They are the CHANGELOG entry and the
  // GitHub Release body, so a name that resolves to nothing reaches operators
  // there exactly as it would from the README, and nothing else looked: this
  // release described a fix as the work of `b.mail.serverNet`, which is an
  // internal module and no namespace at all. Only the current version's file
  // is read, because the shipped ones name the surface of their own release.
  var version = require(nodePath.join(ROOT, "package.json")).version;
  var notes = nodePath.join(ROOT, "release-notes", "v" + version + ".json");
  if (nodeFs.existsSync(notes)) files.push(notes);
  return files;
}

function _resolves(parts) {
  var cur = b;
  for (var i = 0; i < parts.length; i += 1) {
    if (cur === null || cur === undefined) return false;
    if (typeof cur !== "object" && typeof cur !== "function") return false;
    if (!(parts[i] in cur)) return false;
    cur = cur[parts[i]];
  }
  return true;
}

function testEveryDocumentedApiNameResolves() {
  var files = _operatorDocs();
  var scanned = 0;
  var dead = [];
  files.forEach(function (file) {
    var text = nodeFs.readFileSync(file, "utf8");
    var rel  = nodePath.relative(ROOT, file).replace(/\\/g, "/");
    var m;
    REFERENCE_RE.lastIndex = 0;
    while ((m = REFERENCE_RE.exec(text)) !== null) {
      scanned += 1;
      var parts = [m[1]].concat(m[2].slice(1).split("."));
      var name  = "b." + parts.join(".");
      if (_resolves(parts)) continue;
      if (Object.prototype.hasOwnProperty.call(CREATE_HANDLE_SHORTHAND, name)) continue;
      if (Object.prototype.hasOwnProperty.call(DELIBERATELY_ABSENT, name)) continue;
      if (dead.indexOf(name + " (" + rel + ")") === -1) dead.push(name + " (" + rel + ")");
    }
    // A namespace named on its own resolves or it does not, and the member
    // class above cannot see one: `b.atoKillSwitch` carries no member to
    // match, so a namespace that moved under another read as ordinary prose
    // while naming nothing.
    NAMESPACE_RE.lastIndex = 0;
    while ((m = NAMESPACE_RE.exec(text)) !== null) {
      scanned += 1;
      var ns = "b." + m[1];
      if (_resolves([m[1]])) continue;
      if (Object.prototype.hasOwnProperty.call(CREATE_HANDLE_SHORTHAND, ns)) continue;
      if (Object.prototype.hasOwnProperty.call(DELIBERATELY_ABSENT, ns)) continue;
      if (dead.indexOf(ns + " (" + rel + ")") === -1) dead.push(ns + " (" + rel + ")");
    }
  });

  check("the operator-facing documents were actually read",
        files.length >= 3 && scanned > 100, files.length + " files, " + scanned + " references");
  check("every b.<namespace>.<member> an operator-facing document names resolves" +
        (dead.length ? " (" + dead.slice(0, 8).join("; ") + ")" : ""),
        dead.length === 0);
}

// ---------------------------------------------------------------------------
// The same question, asked of lib/ prose.
//
// A comment block above a primitive becomes its wiki page, and the text of a
// thrown error is what an operator reads when they have misconfigured
// something. Nothing resolved the names those carry, so
// `b.breakGlass.unsealRowAsService` told operators to mount
// `b.middleware.requireApiKey`, which has never existed under that name.
// ---------------------------------------------------------------------------

// Everything the framework offers through a handle is written in the house
// shorthand: `b.cache.update` for `b.cache.create().update`. A handle member
// cannot be resolved statically, because the handle only exists once create()
// has run, so a name is accepted when its longest resolving prefix is a
// factory or a namespace that has one and a single segment is left over.
// Two segments are left over when the prose named a namespace that is not
// there at all, which is the drift this looks for: `b.mail.auth.dmarc` stops
// at `b.mail` with `auth.dmarc` unaccounted for, and the primitive is
// `b.mail.dmarc`.
function _isHandleMember(parts) {
  var cur = b, depth = 0;
  for (; depth < parts.length; depth += 1) {
    if (cur === null || cur === undefined) break;
    if (typeof cur !== "object" && typeof cur !== "function") break;
    if (!(parts[depth] in cur)) break;
    cur = cur[parts[depth]];
  }
  if (depth === parts.length) return true;
  if (parts.length - depth !== 1) return false;
  var node = depth === 0 ? b : cur;
  if (node === null || node === undefined) return false;
  if (typeof node === "function") return true;
  if (typeof node !== "object") return false;
  if (typeof node.create !== "function") return false;
  // A factory that also HOLDS namespaces gets no wildcard. `b.mail` has a
  // create() and thirty-odd sub-namespaces, so "one segment left over under a
  // factory" accepted `b.mail.<anything>`: three dead names sat in shipped
  // prose while this gate reported clean — `b.mail.bounce` for `b.mailBounce`,
  // `b.mail.dnsbl` for `b.mail.rbl`, `b.mail.submission` for
  // `b.mail.server.submission`. Under a container the shorthand has to be
  // declared in CREATE_HANDLE_SHORTHAND by name, which is how the operator-doc
  // side of this same gate has always spelled it.
  return !_holdsANamespace(node);
}

// A member that is itself a namespace: an object carrying at least one
// function. A plain data bag does not count, so `DEFAULTS` and `STATES` leave
// the sixty-one leaf factories their shorthand.
function _holdsANamespace(node) {
  return Object.keys(node).some(function (key) {
    var member = node[key];
    if (!member || typeof member !== "object" || Array.isArray(member)) return false;
    return Object.keys(member).some(function (inner) {
      return typeof member[inner] === "function";
    });
  });
}

// Names in lib/ prose that resolve nowhere and are still right.
var LIB_PROSE_ALLOWED = Object.freeze({
  "b.mail.agent.sieve.put": "b.mail.agent.create().sieve.put — the handle nests one level, " +
                            "so two segments are left over and the shorthand rule cannot see it",
  "b.middleware.X":         "the pipeline note writes the factory shape `b.middleware.X(opts)` " +
                            "to say every middleware has one; the X stands for any of them",
});

// Comment lines whole, plus the contents of string literals on code lines. A
// quote-aware scan, because a line holding two string literals reads as one
// span to a regex and swallows the code between them: a local named `b` then
// looks like the framework.
function _proseLines(src) {
  var out = [];
  src.split(/\r?\n/).forEach(function (line, i) {
    var trimmed = line.trim();
    if (trimmed.indexOf("*") === 0 || trimmed.indexOf("//") === 0) {
      out.push([i + 1, line]);
      return;
    }
    var buf = "", quote = null;
    for (var j = 0; j < line.length; j += 1) {
      var ch = line[j];
      if (quote === null) {
        if (ch === '"' || ch === "'" || ch === "`") quote = ch;
        continue;
      }
      if (ch === "\\") { j += 1; continue; }
      if (ch === quote) { quote = null; buf += " "; continue; }
      buf += ch;
    }
    if (buf.indexOf("b.") !== -1) out.push([i + 1, " " + buf]);
  });
  return out;
}

function _libSources() {
  var files = [];
  (function walk(dir) {
    nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      var p = nodePath.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "vendor") walk(p);
        return;
      }
      if (entry.name.slice(-3) === ".js") files.push(p);
    });
  })(nodePath.join(ROOT, "lib"));
  return files;
}

function testEveryApiNameInLibProseResolves() {
  var files = _libSources();
  var scanned = 0;
  var dead = [];
  files.forEach(function (file) {
    var rel = nodePath.relative(ROOT, file).replace(/\\/g, "/");
    _proseLines(nodeFs.readFileSync(file, "utf8")).forEach(function (row) {
      var m;
      REFERENCE_RE.lastIndex = 0;
      while ((m = REFERENCE_RE.exec(row[1])) !== null) {
        scanned += 1;
        // `b.pqcSoftware.ml_dsa_*` names the family, and the member class
        // stops at the underscore, so the reported name is a truncation of
        // the glob rather than a primitive anyone wrote.
        if (row[1][m.index + m[0].length] === "*") continue;
        var parts = [m[1]].concat(m[2].slice(1).split("."));
        var name  = "b." + parts.join(".");
        if (_resolves(parts)) continue;
        if (_isHandleMember(parts)) continue;
        // The house shorthand is declared once. Both halves of this gate read
        // the same map, so a name the operator docs are allowed to write is a
        // name lib/ prose may write, and neither half grows its own copy.
        if (Object.prototype.hasOwnProperty.call(CREATE_HANDLE_SHORTHAND, name)) continue;
        if (Object.prototype.hasOwnProperty.call(LIB_PROSE_ALLOWED, name)) continue;
        if (Object.prototype.hasOwnProperty.call(DELIBERATELY_ABSENT, name)) continue;
        var at = name + " (" + rel + ":" + row[0] + ")";
        if (dead.indexOf(at) === -1) dead.push(at);
      }
    });
  });

  check("the lib/ prose was actually read",
        files.length >= 400 && scanned > 5000, files.length + " files, " + scanned + " references");
  check("every b.<namespace>.<member> named in lib/ prose resolves" +
        (dead.length ? " (" + dead.slice(0, 10).join("; ") + ")" : ""),
        dead.length === 0);
}

function testTheAllowlistsStayHonest() {
  // An entry that starts resolving is drift in the other direction: the
  // shorthand became real, or a removal was undone, and the list is now
  // hiding a name nobody is checking.
  var stale = [];
  Object.keys(CREATE_HANDLE_SHORTHAND).forEach(function (name) {
    if (_resolves(name.split(".").slice(1))) stale.push(name + " now resolves");
  });
  Object.keys(DELIBERATELY_ABSENT).forEach(function (name) {
    if (_resolves(name.split(".").slice(1))) stale.push(name + " is back");
  });
  check("no allowlisted name resolves, so none of them is hiding a live API" +
        (stale.length ? " (" + stale.join("; ") + ")" : ""), stale.length === 0);

  // Every shorthand entry must name a member that really is on the handle,
  // otherwise the allowlist is excusing a wrong name rather than a convention.
  var unbacked = Object.keys(CREATE_HANDLE_SHORTHAND).filter(function (name) {
    var reason = CREATE_HANDLE_SHORTHAND[name];
    return reason.indexOf("create()") === -1;
  });
  check("every shorthand entry records the create()-handle form it stands for" +
        (unbacked.length ? " (" + unbacked.join(", ") + ")" : ""), unbacked.length === 0);
}

async function run() {
  testEveryDocumentedApiNameResolves();
  testEveryApiNameInLibProseResolves();
  testTheAllowlistsStayHonest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[operator-doc-api-names] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
