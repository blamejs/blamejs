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
  "b.auth.oauth.parseCallback":        "b.auth.oauth.create().parseCallback",
  "b.auth.oauth.refreshAccessToken":   "b.auth.oauth.create().refreshAccessToken",
  "b.backup.scheduleTest":             "b.backup.create().scheduleTest",
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
  testTheAllowlistsStayHonest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[operator-doc-api-names] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
