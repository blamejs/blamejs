// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every `someModule().property` read in lib/ names something that module
 * actually exports.
 *
 * A read of an absent property is `undefined`. It does not throw where it is
 * written, it is indistinguishable from "not configured", and it surfaces
 * somewhere else entirely — or nowhere at all:
 *
 *   - `b.mail.send.deliver` resolved its default transport as
 *     `mailModule().smtpTransport`, and `lib/mail.js` exports that transport as
 *     `transports.smtp`. The default was therefore `undefined`, calling it threw
 *     a TypeError, the throw was classified as a transient peer problem, and
 *     every recipient deferred `4.4.4` forever without a socket ever opening.
 *   - `bearer-auth` and `fetch-metadata` counted their refusals through
 *     `observability().count(...)`, which does not exist either. Both calls sit
 *     inside `try { } catch { }` for drop-silent telemetry, so the TypeError was
 *     swallowed on every request and the metric was never emitted once.
 *
 * Neither has a test that could have caught it, because the failure is a NAME
 * rather than a behaviour: every test that passed an explicit transport, or
 * that did not assert on a counter, passed. This file checks the names.
 *
 * It resolves the modules and reads their real exports rather than matching
 * text, so it cannot be satisfied by a rename that only looks right. The one
 * thing it must not do is invent findings: a lazy handle whose body calls
 * something on the module (`require("./log").boot("pubsub")`) yields an
 * INSTANCE, whose properties are nothing to do with the module's exports, so
 * only bare module handles are checked. Reading them as module handles produced
 * sixteen false findings on the first run.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var helpers = require("../helpers");
var check   = helpers.check;

var LIB = path.join(__dirname, "..", "..", "lib");

// Vendored code is not ours to hold to this, and it is large.
function _libFiles(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== "vendor") _libFiles(p, out); return; }
    if (e.name.slice(-3) === ".js") out.push(p);
  });
  return out;
}

// A lazy handle that returns the MODULE and nothing else. The `\}` at the end is
// what excludes `require("./log").boot("pubsub")` and every other shape whose
// value is an instance.
var LAZY_DECLS = [
  /var\s+([A-Za-z_$][\w$]*)\s*=\s*lazyRequire\(\s*function\s*\(\s*\)\s*\{\s*return\s+require\(\s*["']([^"']+)["']\s*\)\s*;?\s*\}/g,
  /function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*return\s+require\(\s*["']([^"']+)["']\s*\)\s*;?\s*\}/g,
];

function testEveryLazyModulePropertyResolves() {
  var files    = _libFiles(LIB, []);
  var findings = [];
  var reads    = 0;

  files.forEach(function (file) {
    var src  = fs.readFileSync(file, "utf8");
    var lazy = Object.create(null);
    LAZY_DECLS.forEach(function (re) {
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(src))) lazy[m[1]] = m[2];
    });

    Object.keys(lazy).forEach(function (name) {
      var mod;
      try { mod = require(path.resolve(path.dirname(file), lazy[name])); }
      catch (_e) { return; }          // not resolvable from here; not this gate's call
      var use = new RegExp(name + "\\(\\)\\.([A-Za-z_$][\\w$]*)", "g");
      var seen = Object.create(null);
      var u;
      while ((u = use.exec(src))) {
        if (seen[u[1]]) continue;
        seen[u[1]] = true;
        // A doc comment showing the idiom is not a call. The `@module` block of
        // `lazy-require` itself demonstrates `db().findOne(...)`.
        var lineStart = src.lastIndexOf("\n", u.index) + 1;
        var line = src.slice(lineStart, src.indexOf("\n", u.index));
        if (line.replace(/^\s+/, "").charAt(0) === "*") continue;
        reads += 1;
        if (!(u[1] in mod)) {
          findings.push(path.relative(LIB, file) + ": " + name + "()." + u[1] +
                        " — " + lazy[name] + " exports no such name");
        }
      }
    });
  });

  // The count is reported so a future reader can see the gate still has reach:
  // a refactor that changed how lazy handles are declared would quietly drop it
  // to zero, and zero reads passing is not the same as zero findings.
  check("every lazy-module property read in lib/ resolves (" + reads +
        " reads across " + files.length + " files)",
        findings.length === 0, findings.join(" | "));
  check("and the gate still reaches a meaningful number of them",
        reads > 300, "reads=" + reads);
}

function run() {
  testEveryLazyModulePropertyResolves();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("[lazy-module-names] OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", (e && e.stack) || e);
    process.exit(1);
  }
}
