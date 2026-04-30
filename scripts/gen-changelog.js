"use strict";
// generates CHANGELOG.md from git tags. one entry per released tag,
// grouped by minor. run before each release; commit the regenerated
// file alongside the version bump.

var cp = require("node:child_process");
var fs = require("node:fs");
var path = require("node:path");

function _git(args) {
  var r = cp.spawnSync("git", args, { encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error("git failed (" + r.status + "): " + (r.stderr || ""));
  }
  return r.stdout;
}

function _tags() {
  var raw = _git([
    "for-each-ref", "refs/tags",
    "--sort=v:refname",
    "--format=%(refname:short)|%(creatordate:short)|%(contents:subject)",
  ]);
  return raw.split("\n").filter(Boolean).map(function (line) {
    var i1 = line.indexOf("|");
    var i2 = line.indexOf("|", i1 + 1);
    var tag = line.slice(0, i1);
    var date = line.slice(i1 + 1, i2);
    var subject = line.slice(i2 + 1);
    // strip the leading "vX.Y.Z — " or "X.Y.Z — " from the subject so the
    // entry doesn't repeat the version that the section header already lists.
    var summary = subject
      .replace(/^v?\d+\.\d+\.\d+\s*[—\-:]\s*/, "")
      .trim();
    return {
      tag:     tag,
      version: tag.replace(/^v/, ""),
      date:    date,
      summary: summary,
    };
  });
}

function _cmpVersion(a, b) {
  var pa = a.split(".").map(function (n) { return Number(n) || 0; });
  var pb = b.split(".").map(function (n) { return Number(n) || 0; });
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var x = pa[i] || 0;
    var y = pb[i] || 0;
    if (x !== y) return x - y;
  }
  return 0;
}

function _groupByMinor(tags) {
  var groups = new Map();
  tags.forEach(function (t) {
    var minor = t.version.split(".").slice(0, 2).join(".");
    if (!groups.has(minor)) groups.set(minor, []);
    groups.get(minor).push(t);
  });
  return Array.from(groups.keys())
    .sort(function (a, b) { return _cmpVersion(b, a); })
    .map(function (m) {
      var entries = groups.get(m).slice().sort(function (a, b) {
        return _cmpVersion(b.version, a.version);
      });
      return { minor: m, entries: entries };
    });
}

function build() {
  var groups = _groupByMinor(_tags());
  var out = [];
  out.push("# Changelog");
  out.push("");
  out.push("One entry per released tag, grouped by minor. Latest first.");
  out.push("");
  out.push("Pre-1.0 the surface is intentionally evolving — every release may");
  out.push("change something operators depend on. Read each entry before");
  out.push("upgrading across more than a few patches at a time.");
  out.push("");
  groups.forEach(function (g) {
    out.push("## v" + g.minor + ".x");
    out.push("");
    g.entries.forEach(function (e) {
      out.push("- **" + e.version + "** (" + e.date + ") — " + e.summary);
    });
    out.push("");
  });
  return out.join("\n");
}

var target = path.resolve(__dirname, "..", "CHANGELOG.md");
fs.writeFileSync(target, build(), "utf8");
process.stdout.write("[gen-changelog] wrote " + target + "\n");
