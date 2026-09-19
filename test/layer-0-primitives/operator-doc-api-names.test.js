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
});

// Names the prose mentions BECAUSE they are gone. Resolving would mean the
// removal had been undone.
var DELIBERATELY_ABSENT = Object.freeze({
  "b.backup.localStorage": "renamed to b.backup.diskStorage in v0.11.2, alias removed in v0.11.20; " +
                           "the Node 26 localStorage note exists to record that removal",
});

// Member names may hold underscores (ml_kem_1024), so a class that stops at
// `_` would report a truncated name that resolves nowhere.
var REFERENCE_RE = /\bb\.([A-Za-z][A-Za-z0-9_]*)((?:\.[A-Za-z][A-Za-z0-9_]*)+)/g;

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
